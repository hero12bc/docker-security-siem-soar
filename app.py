import json
import os
import time
from elasticsearch import Elasticsearch
from kafka import KafkaConsumer, KafkaProducer

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
SOURCE_TOPICS = ["docker-metrics", "docker-logs", "docker-syscalls"]
INCIDENT_TOPIC = "threat-incidents"

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "security-incidents"

# Tín hiệu sẽ tự "hết hạn" sau chừng này giây nếu không có tín hiệu mới cùng loại
# -> tránh vừa dính 1 lần là báo lặp đi lặp lại mãi mãi.
SIGNAL_TTL_SECONDS = 60

state = {}


def extract_container_id(payload: dict) -> str:
    # Thử nhiều kiểu field khác nhau vì Filebeat/Metricbeat/Falco có thể xuất
    # cấu trúc khác nhau tùy phiên bản/cấu hình.
    if "container_id" in payload:
        return payload["container_id"]
    if "container.id" in payload:  # trường hợp field bị "flatten" thành chuỗi có dấu chấm
        return payload["container.id"]
    if "container" in payload:
        c = payload["container"]
        if isinstance(c, dict):
            return c.get("id", "unknown")
        if isinstance(c, str):
            return c
    if "docker" in payload and isinstance(payload["docker"], dict):
        d = payload["docker"].get("container")
        if isinstance(d, dict):
            return d.get("id", "unknown")
    return "unknown"


def get_state(container_id: str) -> dict:
    if container_id not in state:
        state[container_id] = {
            "high_cpu": 0,          # lưu timestamp lần cuối tín hiệu này xảy ra (0 = chưa có)
            "mining_log": 0,
            "suspicious_syscall": 0,
            "signals": {},          # tên_signal -> timestamp lần cuối, để log ra cho dễ đọc
        }
    return state[container_id]


def is_active(last_seen: float) -> bool:
    return last_seen > 0 and (time.time() - last_seen) <= SIGNAL_TTL_SECONDS


def handle_metric(container_id: str, payload: dict) -> None:
    cpu = payload.get("cpu_percent", 0)
    s = get_state(container_id)
    if cpu > 80:
        s["high_cpu"] = time.time()
        s["signals"]["HIGH_CPU"] = s["high_cpu"]


def handle_log(container_id: str, payload: dict) -> None:
    msg = str(payload.get("message", "")).lower()
    s = get_state(container_id)
    keywords = ["stratum+tcp", "xmrig", "pool.minexmr", "monero", "hashrate"]
    matched = [k for k in keywords if k in msg]
    if matched:
        s["mining_log"] = time.time()
        s["signals"]["MINING_LOG_DETECTED"] = s["mining_log"]
        # DEBUG: khi container_id là "unknown", in payload gốc để biết vì sao
        # extract_container_id không nhận diện được, và log gốc chứa từ khóa gì.
        if container_id == "unknown":
            print(f"[DEBUG-UNKNOWN-LOG] matched_keywords={matched} | raw_payload={payload}")


def handle_syscall(container_id: str, payload: dict) -> None:
    rule = str(payload.get("rule", "")).lower()
    output = str(payload.get("output", "")).lower()
    s = get_state(container_id)

    if "xmrig" in output or "miner" in output or "suspicious process" in rule:
        s["suspicious_syscall"] = time.time()
        s["signals"]["SUSPICIOUS_SYSCALL_XMRIG"] = s["suspicious_syscall"]
        if container_id == "unknown":
            print(f"[DEBUG-UNKNOWN-SYSCALL] raw_payload={payload}")


def evaluate(container_id: str):
    s = get_state(container_id)
    score = 0
    active_signals = []

    if is_active(s["high_cpu"]):
        score += 30
        active_signals.append("HIGH_CPU")
    if is_active(s["mining_log"]):
        score += 40
        active_signals.append("MINING_LOG_DETECTED")
    if is_active(s["suspicious_syscall"]):
        score += 30
        active_signals.append("SUSPICIOUS_SYSCALL_XMRIG")

    if score == 0:
        return None

    label = "INFO"
    if score >= 80:
        label = "CRITICAL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 30:
        label = "MEDIUM"

    return {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "container_id": container_id,
        "risk_score": score,
        "label": label,
        "signals": active_signals,
        "rule_name": "CryptoMiner_MultiSignal_Correlation",
    }


es = Elasticsearch(ES_HOST)

producer = None
while producer is None:
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            api_version=(3, 7, 0),
        )
        print(f"[ai_processor] Kết nối Kafka Producer thành công! (bootstrap={KAFKA_BOOTSTRAP})")
    except Exception as e:
        print(f"[+] Đang chờ Kafka sẵn sàng (Producer)... ({e})")
        time.sleep(3)


# Chỉ in lại cùng 1 (container_id, label, signals) một lần trong SIGNAL_TTL_SECONDS
# để tránh spam log khi có nhiều message dồn dập cho cùng 1 sự cố.
_last_printed = {}


def persist_and_alert(incident: dict) -> None:
    try:
        es.index(index=ES_INDEX, document=incident)
    except Exception as e:
        print(f"[ES ERROR] {e}")

    key = (incident["container_id"], incident["label"], tuple(sorted(incident["signals"])))
    now = time.time()
    if key not in _last_printed or (now - _last_printed[key]) > SIGNAL_TTL_SECONDS:
        _last_printed[key] = now
        print(
            f"[{incident['label']}] container={incident['container_id']} "
            f"score={incident['risk_score']} signals={incident['signals']}"
        )

    if incident["label"] == "CRITICAL":
        producer.send(INCIDENT_TOPIC, incident)
        producer.flush()
        print(f"  -> Đã đẩy sự cố CRITICAL sang topic '{INCIDENT_TOPIC}'")


def main() -> None:
    consumer = None
    while consumer is None:
        try:
            consumer = KafkaConsumer(
                *SOURCE_TOPICS,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_deserializer=lambda v: json.loads(
                    v.decode("utf-8", errors="ignore")
                ),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                group_id="ai-detection-engine-v3",
                api_version=(3, 7, 0),
            )
        except Exception as e:
            print(f"[+] Đang chờ Kafka sẵn sàng (Consumer)... ({e})")
            time.sleep(3)

    print(f"[ai_processor] Đang lắng nghe topics: {SOURCE_TOPICS} (bootstrap={KAFKA_BOOTSTRAP})")

    for msg in consumer:
        topic = msg.topic
        try:
            payload = msg.value
        except Exception as e:
            print(f"[PARSE ERROR] {e}")
            continue

        if not isinstance(payload, dict):
            continue

        container_id = extract_container_id(payload)

        if topic == "docker-metrics":
            handle_metric(container_id, payload)
        elif topic == "docker-logs":
            handle_log(container_id, payload)
        elif topic == "docker-syscalls":
            handle_syscall(container_id, payload)

        incident = evaluate(container_id)
        if incident:
            persist_and_alert(incident)


if __name__ == "__main__":
    main()
