import json
import os
import re
import time
from elasticsearch import Elasticsearch
from kafka import KafkaConsumer, KafkaProducer

from scenarios import SCENARIOS, CPU_WEIGHT, CPU_THRESHOLD_PERCENT, SIGNAL_TTL_SECONDS

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
SOURCE_TOPICS = ["docker-metrics", "docker-logs", "docker-syscalls"]
INCIDENT_TOPIC = "threat-incidents"

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "security-incidents"

state = {}


def extract_container_id(payload: dict) -> str:
    # Thử nhiều kiểu field khác nhau vì Filebeat/Metricbeat/Falco có thể xuất
    # cấu trúc khác nhau tùy phiên bản/cấu hình.
    cid = None

    if "container_id" in payload:
        cid = payload["container_id"]
    elif "container.id" in payload:  # trường hợp field bị "flatten" thành chuỗi có dấu chấm
        cid = payload["container.id"]
    else:
        # Cấu trúc thật của Falco/connector: container.id nằm lồng trong output_fields
        output_fields = payload.get("output_fields")
        if isinstance(output_fields, dict) and output_fields.get("container.id"):
            cid = output_fields["container.id"]

    if cid is None and "container" in payload:
        c = payload["container"]
        if isinstance(c, dict):
            cid = c.get("id")
        elif isinstance(c, str):
            cid = c

    if cid is None and isinstance(payload.get("docker"), dict):
        d = payload["docker"].get("container")
        if isinstance(d, dict):
            cid = d.get("id")

    if cid is None:
        # Fallback cuối: Filebeat "type: container" không phải lúc nào cũng đính
        # kèm field container, nhưng đường dẫn file log luôn chứa ID container
        # (do Docker đặt tên thư mục log theo container ID đầy đủ).
        log_obj = payload.get("log")
        if isinstance(log_obj, dict):
            file_obj = log_obj.get("file")
            if isinstance(file_obj, dict):
                path = file_obj.get("path", "")
                match = re.search(r"/containers/([0-9a-f]{12,64})/", path)
                if match:
                    cid = match.group(1)

    if not cid:
        return "unknown"

    # QUAN TRỌNG: chuẩn hóa về 12 ký tự đầu cho MỌI nguồn. Falco thường trả về
    # ID rút gọn 12 ký tự, còn Metricbeat/Filebeat trả về ID đầy đủ 64 ký tự —
    # nếu không cắt về cùng độ dài, các tín hiệu của CÙNG một container sẽ bị
    # ghi vào 2 "bucket" khác nhau và không bao giờ tương quan được với nhau.
    return cid[:12]


def get_state(container_id: str) -> dict:
    if container_id not in state:
        state[container_id] = {
            "cpu_high_at": 0,   # timestamp lần cuối CPU vượt ngưỡng (0 = chưa có)
            "signals": {},      # "LOG:<scenario>" / "SYSCALL:<scenario>" -> timestamp lần cuối
        }
    return state[container_id]


def is_active(last_seen: float) -> bool:
    return last_seen > 0 and (time.time() - last_seen) <= SIGNAL_TTL_SECONDS


def handle_metric(container_id: str, payload: dict) -> None:
    cpu = payload.get("cpu_percent")

    if cpu is None:
        # Ưu tiên lấy từ cấu trúc chuẩn của Metricbeat: docker.cpu.total.pct
        docker_obj = payload.get("docker", {})
        if isinstance(docker_obj, dict):
            cpu_obj = docker_obj.get("cpu", {})
            if isinstance(cpu_obj, dict):
                total = cpu_obj.get("total", {})
                if isinstance(total, dict) and "pct" in total:
                    cpu = total["pct"] * 100

    # Fallback cho trường hợp cpu nằm ở root
    if cpu is None:
        cpu_obj = payload.get("cpu", {})
        if isinstance(cpu_obj, dict):
            total = cpu_obj.get("total", {})
            if isinstance(total, dict) and "pct" in total:
                cpu = total["pct"] * 100

    if cpu is None:
        return

    s = get_state(container_id)
    if cpu > CPU_THRESHOLD_PERCENT:
        s["cpu_high_at"] = time.time()


def handle_log(container_id: str, payload: dict) -> None:
    msg = str(payload.get("message", "")).lower()
    if not msg:
        return
    s = get_state(container_id)
    for name, cfg in SCENARIOS.items():
        matched = [kw for kw in cfg["log_keywords"] if kw in msg]
        if matched:
            s["signals"][f"LOG:{name}"] = time.time()
            if container_id == "unknown":
                print(f"[DEBUG-UNKNOWN-LOG] scenario={name} matched_keywords={matched} | raw_payload={payload}")


def handle_syscall(container_id: str, payload: dict) -> None:
    rule = str(payload.get("rule", "")).lower()
    output = str(payload.get("output", "")).lower()
    s = get_state(container_id)
    for name, cfg in SCENARIOS.items():
        hit_output = any(kw in output for kw in cfg["syscall_output_kw"])
        hit_rule = any(kw in rule for kw in cfg["syscall_rule_kw"])
        if hit_output or hit_rule:
            s["signals"][f"SYSCALL:{name}"] = time.time()
            if container_id == "unknown":
                print(f"[DEBUG-UNKNOWN-SYSCALL] scenario={name} raw_payload={payload}")


def evaluate(container_id: str):
    """
    Tính điểm risk score CHO TỪNG kịch bản đang active, rồi chọn ra kịch bản
    có điểm cao nhất để báo cáo (một container có thể khớp nhiều kịch bản
    cùng lúc, nhưng ta báo cáo kịch bản đáng ngờ nhất tại thời điểm đó).
    """
    s = get_state(container_id)
    cpu_active = is_active(s["cpu_high_at"])

    best = None  # (score, scenario_name, active_signal_labels)

    for name, cfg in SCENARIOS.items():
        score = 0
        active = []

        log_ts = s["signals"].get(f"LOG:{name}", 0)
        syscall_ts = s["signals"].get(f"SYSCALL:{name}", 0)

        if is_active(log_ts):
            score += cfg["weight_log"]
            active.append(f"LOG_{name.upper()}")
        if is_active(syscall_ts):
            score += cfg["weight_syscall"]
            active.append(f"SYSCALL_{name.upper()}")
        if cfg.get("uses_cpu_signal") and cpu_active:
            score += CPU_WEIGHT
            active.append("HIGH_CPU")

        if score > 0 and (best is None or score > best[0]):
            best = (score, name, active)

    if best is None:
        return None

    score, scenario, active_signals = best

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
        "scenario": scenario,
        "scenario_label": SCENARIOS[scenario]["label"],
        "signals": active_signals,
        "rule_name": f"{scenario}_MultiSignal_Correlation",
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


# Chỉ in lại cùng 1 (container_id, scenario, label, signals) một lần trong
# SIGNAL_TTL_SECONDS để tránh spam log khi có nhiều message dồn dập.
_last_printed = {}


def persist_and_alert(incident: dict) -> None:
    try:
        es.index(index=ES_INDEX, document=incident)
    except Exception as e:
        print(f"[ES ERROR] {e}")

    key = (
        incident["container_id"],
        incident["scenario"],
        incident["label"],
        tuple(sorted(incident["signals"])),
    )
    now = time.time()
    if key not in _last_printed or (now - _last_printed[key]) > SIGNAL_TTL_SECONDS:
        _last_printed[key] = now
        print(
            f"[{incident['label']}] container={incident['container_id']} "
            f"scenario={incident['scenario']} score={incident['risk_score']} "
            f"signals={incident['signals']}"
        )

    if incident["label"] == "CRITICAL":
        producer.send(INCIDENT_TOPIC, incident)
        producer.flush()
        print(f"  -> Đã đẩy sự cố CRITICAL ({incident['scenario']}) sang topic '{INCIDENT_TOPIC}'")


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
    print(f"[ai_processor] Các kịch bản đang bật: {list(SCENARIOS.keys())}")

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
