"""
ai_rule_generator/apply_rules.py
Giai đoạn 6 (bổ sung) — Bán tự động áp dụng luật đã được AI sinh ra

Đọc generated_rules.yaml (do generator.py tạo ra), hiển thị từng luật, hỏi
xác nhận (y/n) từng luật một. Luật được đồng ý sẽ ghi vào approved_rules.yaml
(file thường, không cần quyền root). Sau khi chạy xong, script in sẵn lệnh
sudo tee để bạn tự tay nối approved_rules.yaml vào file luật Falco thật —
tách riêng bước cần quyền root để tránh script tự ý sửa file hệ thống.
"""

import sys

import yaml

INPUT_FILE = "generated_rules.yaml"
OUTPUT_FILE = "approved_rules.yaml"


def load_rules(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Không tìm thấy {path}. Chạy generator.py trước để sinh luật.")
        sys.exit(1)

    if not isinstance(data, list):
        print(f"{path} không đúng định dạng danh sách luật.")
        sys.exit(1)

    return data


def print_rule(rule: dict, index: int) -> None:
    print(f"\n----- Luật #{index} -----")
    print(f"Tên       : {rule.get('rule')}")
    print(f"Mô tả     : {rule.get('desc')}")
    print(f"Điều kiện : {rule.get('condition')}")
    print(f"Output    : {rule.get('output')}")
    print(f"Mức độ    : {rule.get('priority')}")
    print(f"Tags      : {rule.get('tags', [])}")


def main():
    rules = load_rules(INPUT_FILE)
    approved = []

    print(f"Đã nạp {len(rules)} luật từ {INPUT_FILE}. Duyệt từng luật một:\n")

    for i, rule in enumerate(rules, start=1):
        print_rule(rule, i)
        answer = input("Áp dụng luật này? (y/n): ").strip().lower()
        if answer == "y":
            approved.append(rule)
            print("  -> Đã chấp nhận.")
        else:
            print("  -> Bỏ qua.")

    if not approved:
        print("\nKhông có luật nào được chấp nhận. Không ghi gì thêm.")
        return

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(approved, f, allow_unicode=True, sort_keys=False)

    print(f"\nĐã ghi {len(approved)} luật được duyệt vào {OUTPUT_FILE}.")
    print("\nBước cuối (thủ công, cần quyền root để sửa file luật Falco thật):")
    print("  1. Kiểm tra lại lần nữa:  cat approved_rules.yaml")
    print("  2. Nối vào file luật Falco thật, ví dụ:")
    print("     sudo tee -a /etc/falco/falco_rules.yaml < approved_rules.yaml")
    print("     (đổi đúng đường dẫn file rules Falco bạn đang dùng nếu khác)")
    print("  3. Khởi động lại Falco để nạp luật mới:")
    print("     sudo systemctl restart falco   # hoặc cách bạn đã chạy Falco ở Giai đoạn 0")


if __name__ == "__main__":
    main()
