"""
test_simulate_attack.py
Bơm 3 message giả lập (metric CPU cao, log chứa từ khóa mining pool,
syscall khả nghi) vào đúng 3 topic Kafka, cùng chung container_id,
để kiểm tra ai_processor có tương quan và bắn CRITICAL hay không.

Chạy: python test_simulate_attack.py
(cần cài kafka-python: pip install kafka-python --break-system-packages)
"""

import json
import time
from datetime import datetime, timezone

from kafka import KafkaProducer

KAFKA_BOOTSTRAP = "localhost:9092"   # chạy từ host, không phải trong container
CONTAINER_ID = "df30114e6887"

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)


def ts():
    return datetime.now(timezone.utc).isoformat()


def send(topic, payload):
    producer.send(topic, payload)
    producer.flush()
    print(f"-> Đã gửi tới {topic}: {payload}")


if __name__ == "__main__":
    # 1. Metric: CPU tăng vọt
    send("docker-metrics", {
        "timestamp": ts(),
        "container_id": CONTAINER_ID,
        "source": "metricbeat",
        "cpu_percent": 95.5,
    })
    time.sleep(1)

    # 2. Log: chứa từ khóa mining pool
    send("docker-logs", {
        "timestamp": ts(),
        "container_id": CONTAINER_ID,
        "source": "filebeat",
        "message": "connecting to pool stratum+tcp://xmrig.pool.minexmr.com:4444",
    })
    time.sleep(1)

    # 3. Syscall: rule Falco khả nghi
    send("docker-syscalls", {
        "timestamp": ts(),
        "container_id": CONTAINER_ID,
        "source": "falco",
        "rule": "Suspicious process spawned",
        "output": "Suspicious process spawned in container (proc=xmrig)",
    })

    print("\nĐã gửi đủ 3 tín hiệu. Kiểm tra log ai_processor "
          "(docker compose logs -f ai_processor) — kỳ vọng thấy dòng [CRITICAL].")
