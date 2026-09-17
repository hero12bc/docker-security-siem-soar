"""
incident_responder/app.py
Giai đoạn 4 — SOAR Incident Response

Đọc topic 'threat-incidents' (chỉ chứa sự cố CRITICAL do ai_processor đẩy sang),
dùng Docker SDK để tự động dừng (hoặc cô lập mạng) container bị nhiễm,
ghi log hành động đã thực hiện vào Elasticsearch để phục vụ báo cáo.
"""

import json
import os
import time
from datetime import datetime, timezone

import docker
import requests
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
INCIDENT_TOPIC = "threat-incidents"

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "incident-response-actions"

# Giai đoạn 5: Connector Gateway - nơi gửi cảnh báo ra Telegram/Zalo/PfSense
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:2802/alert")


def notify_gateway(record: dict) -> None:
    try:
        requests.post(GATEWAY_URL, json=record, timeout=5)
    except Exception as e:
        print(f"[GATEWAY ERROR] Không gọi được Connector Gateway: {e}")

# "stop"    -> dừng hẳn container (an toàn, chắc chắn nhất, dùng để demo)
# "isolate" -> chỉ ngắt container khỏi mọi network, giữ tiến trình chạy
#              (hữu ích nếu muốn giữ nguyên hiện trường để điều tra thêm)
RESPONSE_ACTION = os.getenv("RESPONSE_ACTION", "stop")

es = Elasticsearch(ES_HOST)

docker_client = None
while docker_client is None:
    try:
        docker_client = docker.from_env()
        docker_client.ping()
        print("[incident_responder] Kết nối Docker daemon thành công!")
    except Exception as e:
        print(f"[+] Đang chờ Docker daemon sẵn sàng... ({e})")
        time.sleep(3)


def log_action(incident: dict, action: str, status: str, detail: str = "") -> None:
    record = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "container_id": incident.get("container_id"),
        "risk_score": incident.get("risk_score"),
        "label": incident.get("label"),
        "signals": incident.get("signals"),
        "action": action,
        "action_status": status,
        "detail": detail,
    }
    try:
        es.index(index=ES_INDEX, document=record)
    except Exception as e:
        print(f"[ES ERROR] Không ghi được log hành động: {e}")

    print(
        f"[SOAR] container={record['container_id']} action={action} "
        f"status={status} {detail}"
    )

    # Chỉ gửi cảnh báo ra ngoài khi hành động THẬT SỰ thành công,
    # tránh spam Telegram với các sự cố test/not_found/skipped.
    if status == "success":
        notify_gateway(record)


def isolate_container(container) -> None:
    """Ngắt container khỏi mọi network đang kết nối, không dừng tiến trình."""
    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    for net_name in networks:
        try:
            network = docker_client.networks.get(net_name)
            network.disconnect(container, force=True)
        except Exception as e:
            print(f"[SOAR] Lỗi khi ngắt network '{net_name}': {e}")


def handle_incident(incident: dict) -> None:
    container_id = incident.get("container_id")

    if not container_id or container_id == "unknown":
        log_action(incident, RESPONSE_ACTION, "skipped",
                    "container_id không xác định, bỏ qua để tránh xử lý nhầm")
        return

    try:
        container = docker_client.containers.get(container_id)
    except docker.errors.NotFound:
        log_action(
            incident, RESPONSE_ACTION, "not_found",
            f"Không tìm thấy container '{container_id}' đang chạy "
            f"(có thể là dữ liệu test giả lập, không phải container thật)",
        )
        return
    except Exception as e:
        log_action(incident, RESPONSE_ACTION, "error", str(e))
        return

    try:
        if RESPONSE_ACTION == "isolate":
            isolate_container(container)
            log_action(incident, "isolate", "success")
        else:
            container.stop(timeout=5)
            log_action(incident, "stop", "success")
    except Exception as e:
        log_action(incident, RESPONSE_ACTION, "error", str(e))


def main() -> None:
    consumer = None
    while consumer is None:
        try:
            consumer = KafkaConsumer(
                INCIDENT_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_deserializer=lambda v: json.loads(
                    v.decode("utf-8", errors="ignore")
                ),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                group_id="soar-incident-responder",
                api_version=(3, 7, 0),
            )
        except Exception as e:
            print(f"[+] Đang chờ Kafka sẵn sàng... ({e})")
            time.sleep(3)

    print(
        f"[incident_responder] Đang lắng nghe topic: {INCIDENT_TOPIC} "
        f"(bootstrap={KAFKA_BOOTSTRAP}, action={RESPONSE_ACTION})"
    )

    for msg in consumer:
        try:
            incident = msg.value
        except Exception as e:
            print(f"[PARSE ERROR] {e}")
            continue

        if not isinstance(incident, dict):
            continue

        if incident.get("label") == "CRITICAL":
            handle_incident(incident)


if __name__ == "__main__":
    main()
