"""
ai_rule_generator/generator.py
Giai đoạn 6 — AI Rule Generator (Ollama)

Nhận 1 luật mẫu (Seed Rule) + 1 đoạn log/sự cố mẫu, dùng Ollama (LLM chạy local,
không gửi dữ liệu ra ngoài) để sinh ra các biến thể luật Falco mới, sau đó
validate cú pháp (parse được YAML, đủ field bắt buộc) trước khi coi là hợp lệ.
Luật hợp lệ được ghi ra generated_rules.yaml để review thủ công trước khi áp
dụng vào falco_rules.yaml thật.
"""

import os
import re

import requests
import yaml

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")

REQUIRED_FIELDS = {"rule", "desc", "condition", "output", "priority"}

SEED_FALCO_RULE = """- rule: Suspicious CryptoMiner Process
  desc: Phát hiện tiến trình nghi ngờ đào tiền ảo trong container
  condition: spawned_process and container and proc.name in (xmrig, minerd, cpuminer)
  output: "Cảnh báo CryptoMiner (container=%container.id proc=%proc.name cmdline=%proc.cmdline)"
  priority: CRITICAL
  tags: [process, mitre_execution]
"""

SAMPLE_INCIDENT_LOG = """container_id: victim_test_001
process: xmrig
cmdline: xmrig -o pool.minexmr.com:4444 -u WALLET_ADDRESS -p x
network: stratum+tcp://pool.minexmr.com:4444
cpu_percent: 95.5
"""


def build_prompt(seed_rule: str, incident_log: str, n_variants: int = 3) -> str:
    return f"""Bạn là chuyên gia viết luật phát hiện xâm nhập cho Falco (định dạng YAML).

Dưới đây là 1 luật mẫu (Seed Rule) và 1 đoạn log sự cố thật liên quan tới CryptoMiner:

SEED RULE:
{seed_rule}

LOG SỰ CỐ:
{incident_log}

Hãy sinh ra CHÍNH XÁC {n_variants} biến thể luật Falco mới (định dạng YAML là một
danh sách các mapping, mỗi phần tử có đủ các field: rule, desc, condition, output,
priority), nhằm bắt được các biến thể tấn công tương tự (ví dụ: đổi tên tiến trình
miner khác, đổi cổng/pool khác, thêm điều kiện kết nối mạng ra ngoài...).

CHỈ trả về YAML thuần túy dạng list (không bọc trong key "rules:"), bắt đầu ngay
bằng "- rule:". KHÔNG giải thích trước hay sau, KHÔNG viết thêm bất kỳ văn bản
nào ngoài khối YAML. Nếu cần dùng markdown code fence thì chỉ dùng đúng 1 khối
```yaml ... ``` duy nhất, không viết gì thêm bên ngoài khối đó.
"""


def call_ollama(prompt: str) -> str:
    payload = {"model": MODEL, "prompt": prompt, "stream": False}
    resp = requests.post(OLLAMA_URL, json=payload, timeout=600)
    resp.raise_for_status()
    return resp.json().get("response", "")


def extract_yaml_block(raw_text: str) -> str:
    """Nếu AI bọc trong ```yaml ... ``` (kể cả kèm giải thích trước/sau),
    chỉ lấy đúng phần bên trong code fence. Nếu không có fence, dùng nguyên văn."""
    match = re.search(r"```(?:yaml)?\s*(.*?)```", raw_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return raw_text.strip()


def validate_falco_rules(raw_yaml: str):
    """Trả về (danh sách rule hợp lệ, danh sách lỗi)."""
    cleaned = extract_yaml_block(raw_yaml)

    try:
        parsed = yaml.safe_load(cleaned)
    except yaml.YAMLError as e:
        return [], [f"Lỗi parse YAML tổng thể: {e}"]

    # Chấp nhận cả 2 dạng: danh sách trần, hoặc dict bọc ngoài bằng key 'rules'
    if isinstance(parsed, dict) and "rules" in parsed:
        parsed = parsed["rules"]

    if not isinstance(parsed, list):
        return [], ["Kết quả không phải danh sách rule (list) như yêu cầu"]

    valid_rules, errors = [], []
    for i, rule in enumerate(parsed):
        if not isinstance(rule, dict):
            errors.append(f"Rule #{i}: không phải dạng mapping hợp lệ")
            continue
        missing = REQUIRED_FIELDS - set(rule.keys())
        if missing:
            errors.append(f"Rule #{i} ('{rule.get('rule', '?')}'): thiếu field {missing}")
            continue
        valid_rules.append(rule)

    return valid_rules, errors


def main():
    prompt = build_prompt(SEED_FALCO_RULE, SAMPLE_INCIDENT_LOG, n_variants=2)
    print(f"[ai_rule_generator] Đang gọi Ollama ({MODEL}) sinh luật mới, vui lòng đợi...")

    raw_output = call_ollama(prompt)

    print("\n===== OUTPUT THÔ TỪ AI =====")
    print(raw_output)

    valid_rules, errors = validate_falco_rules(raw_output)

    print(f"\n===== KẾT QUẢ VALIDATE: {len(valid_rules)} luật hợp lệ, {len(errors)} lỗi =====")
    for e in errors:
        print(f"  [LỖI] {e}")

    if valid_rules:
        out_path = "generated_rules.yaml"
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(valid_rules, f, allow_unicode=True, sort_keys=False)
        print(f"\nĐã ghi {len(valid_rules)} luật hợp lệ vào {out_path}")
        print("Bước tiếp theo (thủ công/bán tự động): review rồi mới append vào falco_rules.yaml thật.")
    else:
        print("\nKhông có luật nào hợp lệ để ghi ra file. Thử chạy lại (model có thể ra kết quả khác mỗi lần).")


if __name__ == "__main__":
    main()
