"""
ai_processor/scenarios.py
Định nghĩa các "kịch bản tấn công" (attack scenarios) mà ai_processor nhận diện.

MUỐN THÊM 1 KỊCH BẢN MỚI (không đụng tới app.py):
  1. Thêm 1 key mới vào dict SCENARIOS bên dưới, ví dụ "web_shell": {...}
  2. Xong. app.py sẽ tự động dùng scenario mới này khi tính risk score,
     miễn là log/syscall đi vào chứa đúng từ khóa bạn khai báo.

Mỗi kịch bản gồm các field:
  label              : tên hiển thị (tiếng Việt/Anh tùy bạn)
  log_keywords       : list từ khóa (lowercase) để match message trong docker-logs
  syscall_output_kw  : list từ khóa để match field 'output' của event Falco
  syscall_rule_kw    : list từ khóa để match field 'rule' của event Falco
  weight_log         : điểm cộng khi tín hiệu log khớp và còn "active" (trong TTL)
  weight_syscall     : điểm cộng khi tín hiệu syscall khớp và còn "active"
  uses_cpu_signal    : True nếu CPU tăng vọt cũng nên tính là 1 tín hiệu ủng hộ
                        kịch bản này (ví dụ: miner làm CPU cao thật, nhưng
                        brute-force SSH thì không nhất thiết liên quan CPU)

Ghi chú: đây là bộ từ khóa mẫu/khởi điểm, không phải rule Falco đầy đủ.
Với các kịch bản mới bạn tự thêm, nên tinh chỉnh lại từ khóa theo log/syscall
thật của môi trường bạn để giảm false positive.
"""

SCENARIOS = {
    "cryptominer": {
        "label": "Crypto Miner",
        "log_keywords": ["stratum+tcp", "xmrig", "pool.minexmr", "monero", "hashrate"],
        "syscall_output_kw": ["xmrig", "miner"],
        "syscall_rule_kw": ["suspicious process"],
        "weight_log": 40,
        "weight_syscall": 30,
        "uses_cpu_signal": True,
    },

    # ---- Ví dụ kịch bản MỚI được thêm vào, không thay thế cái trên ----
    "reverse_shell": {
        "label": "Reverse Shell",
        "log_keywords": ["bash -i", "sh -i", "nc -e", "ncat -e", "/dev/tcp/", "0>&1"],
        "syscall_output_kw": ["nc ", "ncat", "/bin/sh -i", "/bin/bash -i"],
        "syscall_rule_kw": ["reverse shell", "terminal shell in container"],
        "weight_log": 40,
        "weight_syscall": 40,
        "uses_cpu_signal": False,
    },
    "ssh_bruteforce": {
        "label": "SSH Brute Force",
        "log_keywords": ["failed password", "authentication failure", "invalid user"],
        "syscall_output_kw": ["sshd"],
        "syscall_rule_kw": ["brute force", "repeated login failure"],
        "weight_log": 35,
        "weight_syscall": 20,
        "uses_cpu_signal": False,
    },
    "data_exfiltration": {
        "label": "Data Exfiltration",
        "log_keywords": ["curl -t", "scp ", "tar czf", "/etc/shadow", "base64 -w0"],
        "syscall_output_kw": ["curl", "scp", "wget", "rclone"],
        "syscall_rule_kw": ["sensitive file", "unexpected outbound"],
        "weight_log": 40,
        "weight_syscall": 40,
        "uses_cpu_signal": False,
    },
}

# Tín hiệu CPU cao dùng chung cho mọi kịch bản có uses_cpu_signal=True
CPU_WEIGHT = 30
CPU_THRESHOLD_PERCENT = 80

# Tín hiệu tự "hết hạn" sau chừng này giây nếu không lặp lại
SIGNAL_TTL_SECONDS = 240
