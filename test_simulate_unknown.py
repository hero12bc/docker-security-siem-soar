"""
test_simulate_unknown.py
Giả lập cảnh báo Falco về các hành vi MÀ HỆ THỐNG CHƯA CÓ KỊCH BẢN NÀO bao phủ
(zero-day), để kiểm tra luồng: ai_processor phát hiện hành vi lạ
-> rule_proposer nhờ AI sinh luật -> Telegram có nút Duyệt/Từ chối.

Chạy:
  python3 test_simulate_unknown.py            # mặc định: scan (quét mạng bằng nmap)
  python3 test_simulate_unknown.py list       # liệt kê các tình huống
  python3 test_simulate_unknown.py escape     # chạy 1 tình huống
  python3 test_simulate_unknown.py all        # gửi tất cả (rule_proposer xử lý lần lượt, mỗi cái 1-2 phút)
(cần: pip3 install kafka-python --break-system-packages)

Lưu ý: ai_processor chỉ báo lại cùng 1 tên luật sau 1 giờ. Muốn chạy lại ngay thì
`docker compose restart ai_processor`, và xóa đề xuất cũ trong Elasticsearch:
  curl -X DELETE http://localhost:9200/rule-proposals/_doc/<id>
"""

import json
import sys
import time
from datetime import datetime, timezone

from kafka import KafkaProducer

KAFKA_BOOTSTRAP = "localhost:9092"

# Mỗi tình huống dùng container id riêng và tên luật riêng.
# Từ khóa của 4 kịch bản có sẵn (curl, wget, scp, sshd, "nc ", miner, ...) cố ý KHÔNG xuất hiện
# trong output, để chắc chắn đây là hành vi "chưa có kịch bản nào bao phủ".
SCENARIOS = {
    "scan": {
        "mo_ta": "Quét mạng nội bộ bằng nmap",
        "rule": "Network Scanner Spawned In Container",
        "container": ("abc123def456", "victim_scan"),
        "proc": "nmap", "cmdline": "nmap -sS 10.0.0.0/24",
    },
    "escape": {
        "mo_ta": "Thoát container: nsenter vào namespace của host (PID 1)",
        "rule": "Namespace Entry From Container",
        "container": ("bbb222ccc333", "victim_escape"),
        "proc": "nsenter", "cmdline": "nsenter --target 1 --mount --uts --ipc --net --pid -- sh",
    },
    "setuid": {
        "mo_ta": "Leo thang đặc quyền: bật bit setuid cho /bin/bash",
        "rule": "Setuid Bit Set On Shell Binary",
        "container": ("ddd444eee555", "victim_setuid"),
        "proc": "chmod", "cmdline": "chmod u+s /bin/bash",
    },
    "logwipe": {
        "mo_ta": "Xóa dấu vết: xóa toàn bộ log hệ thống",
        "rule": "System Logs Deleted In Container",
        "container": ("fff666aaa777", "victim_logwipe"),
        "proc": "rm", "cmdline": "rm -rf /var/log/auth.log /var/log/syslog",
    },
    "cron": {
        "mo_ta": "Cài persistence: sửa crontab của root",
        "rule": "Crontab Modified In Container",
        "container": ("111888bbb999", "victim_cron"),
        "proc": "crontab", "cmdline": "crontab -e",
    },
}


def build_event(s):
    cid, name = s["container"]
    return {
        "time": datetime.now(timezone.utc).isoformat(),
        "rule": s["rule"],
        "priority": "Warning",   # phải >= Warning thì mới được coi là hành vi lạ
        "output": f"{s['rule']} (container={cid} proc={s['proc']} cmdline={s['cmdline']})",
        "output_fields": {
            "container.id": cid,
            "container.name": name,
            "proc.name": s["proc"],
            "proc.cmdline": s["cmdline"],
            "user.name": "root",
        },
    }


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if arg == "list":
        for k, s in SCENARIOS.items():
            print(f"  {k:8s} {s['mo_ta']}")
        return
    if arg == "all":
        chosen = list(SCENARIOS)
    elif arg in SCENARIOS:
        chosen = [arg]
    else:
        sys.exit(f"Không có tình huống '{arg}'. Chạy: python3 {sys.argv[0]} list")

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    for k in chosen:
        producer.send("docker-syscalls", build_event(SCENARIOS[k]))
        print(f"Đã gửi: {k} - {SCENARIOS[k]['mo_ta']}")
        time.sleep(1)
    producer.flush()
    print("Theo dõi:")
    print("  docker compose logs -f ai_processor    # kỳ vọng dòng [UNKNOWN-THREAT]")
    print("  docker compose logs -f rule_proposer   # AI sinh luật (1-2 phút/luật), rồi tin Telegram có nút duyệt")


if __name__ == "__main__":
    main()
