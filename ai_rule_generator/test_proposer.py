"""
Kiểm thử proposer.py KHÔNG cần Kafka/Elasticsearch/Ollama/Telegram thật.
Chạy:  cd ai_rule_generator && python3 test_proposer.py
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proposer  # noqa: E402


class FakeES:
    def __init__(self):
        self.docs = {}

    def exists(self, index, id):
        return id in self.docs

    def index(self, index, id, document, refresh=False):
        self.docs[id] = dict(document)

    def get(self, index, id):
        if id not in self.docs:
            raise KeyError(id)
        return {"_source": dict(self.docs[id])}

    def update(self, index, id, doc, refresh=False):
        self.docs[id].update(doc)


calls = []


def fake_tg(method, **payload):
    calls.append((method, payload))
    return {"ok": True, "result": []}


def sent(method):
    return [p for m, p in calls if m == method]


GOOD_AI_OUTPUT = """```yaml
- rule: Network Scanner Spawned
  desc: Phat hien cong cu quet mang trong container
  condition: spawned_process and container and proc.name in (nmap, masscan)
  output: "Scanner alert (proc=%proc.name cmdline=%proc.cmdline)"
  priority: warning
```"""

GENERIC_AI_OUTPUT = """- rule: Catch Everything
  desc: Bat moi thu
  condition: container
  output: "x %container.id"
  priority: WARNING
"""

EVENT = {
    "container_id": "abc123def456", "rule": "Network Scanner Spawned", "priority": "Warning",
    "output": "nmap launched", "fields": {"proc.name": "nmap"},
}


def setup(tmp):
    calls.clear()
    proposer.tg = fake_tg
    proposer.TOKEN, proposer.CHAT_ID, proposer.APPROVER_IDS = "t", "42", set()
    proposer.RULES_OUT_DIR = Path(tmp)
    return FakeES()


def cb(pid, action, chat=42, user=7, mid=99):
    return {"id": "cb1", "data": f"{action}:{pid}", "from": {"id": user, "username": "tuan"},
            "message": {"message_id": mid, "chat": {"id": chat}}}


with tempfile.TemporaryDirectory() as tmp:
    # 1) Chuẩn hóa luật AI sinh ra
    es = setup(tmp)
    proposer.call_ollama = lambda prompt: GOOD_AI_OUTPUT
    pid = proposer.proposal_id("Network Scanner Spawned")
    rule, errs = proposer.generate_rule(EVENT, pid)
    assert rule["rule"] == f"Network Scanner Spawned [AI-{pid}]", rule["rule"]
    assert rule["priority"] == "WARNING"
    assert "%container.id" in rule["output"], rule["output"]
    assert "ai_generated" in rule["tags"]
    print("1 OK  chuẩn hóa: hậu tố [AI-id], priority in hoa, tự thêm %container.id, tag ai_generated")

    # 2) Luật quá chung chung bị loại
    proposer.call_ollama = lambda prompt: GENERIC_AI_OUTPUT
    rule, errs = proposer.generate_rule(EVENT, pid)
    assert rule is None and any("chung chung" in e for e in errs)
    print("2 OK  luật 'condition: container' bị loại")

    # 3) Hành vi lạ mới -> lưu pending + gửi Telegram có 2 nút
    es = setup(tmp)
    proposer.call_ollama = lambda prompt: GOOD_AI_OUTPUT
    proposer.handle_event(es, EVENT)
    assert es.docs[pid]["status"] == "pending"
    msg = sent("sendMessage")[0]
    buttons = msg["reply_markup"]["inline_keyboard"][0]
    assert [b["callback_data"] for b in buttons] == [f"approve:{pid}", f"reject:{pid}"]
    assert "Network Scanner Spawned" in msg["text"] and msg["chat_id"] == "42"
    print("3 OK  lưu pending + Telegram có nút Duyệt/Từ chối")

    # 4) Cùng hành vi lần 2 -> không gọi AI, không gửi thêm
    n = len(calls)
    proposer.call_ollama = lambda prompt: (_ for _ in ()).throw(AssertionError("không được gọi AI lần 2"))
    proposer.handle_event(es, EVENT)
    assert len(calls) == n
    print("4 OK  chống đề xuất trùng")

    # 5) Người lạ (chat khác) bấm Duyệt -> bị từ chối, không ghi file
    proposer.handle_callback(es, cb(pid, "approve", chat=999))
    assert es.docs[pid]["status"] == "pending" and not list(Path(tmp).glob("*"))
    assert sent("answerCallbackQuery")[-1]["show_alert"] is True
    print("5 OK  chat không được phép -> từ chối, không ghi file")

    # 6) Đúng chat nhưng sai user khi có APPROVER_IDS
    proposer.APPROVER_IDS = {"1"}
    proposer.handle_callback(es, cb(pid, "approve", user=7))
    assert es.docs[pid]["status"] == "pending"
    proposer.APPROVER_IDS = set()
    print("6 OK  APPROVER_IDS chặn user không có trong danh sách")

    # 7) Duyệt hợp lệ -> ghi file, ES approved, gỡ nút
    proposer.handle_callback(es, cb(pid, "approve"))
    f = Path(tmp) / f"ai-{pid}.yaml"
    assert f.exists() and not list(Path(tmp).glob("*.tmp"))
    import yaml
    loaded = yaml.safe_load(f.read_text(encoding="utf-8"))
    assert loaded[0]["rule"].endswith(f"[AI-{pid}]")
    assert es.docs[pid]["status"] == "approved" and es.docs[pid]["decided_by"] == "tuan"
    assert sent("editMessageReplyMarkup")
    print("7 OK  duyệt -> ghi", f.name, "(YAML đọc lại được), ES=approved, gỡ nút")

    # 8) Bấm lần 2 -> báo đã xử lý
    proposer.handle_callback(es, cb(pid, "reject"))
    assert es.docs[pid]["status"] == "approved"
    assert "đã được xử lý" in sent("answerCallbackQuery")[-1]["text"]
    print("8 OK  bấm lần 2 không đổi trạng thái")

    # 9) Từ chối -> không ghi file
    es2 = setup(tmp + "/r")
    proposer.call_ollama = lambda prompt: GOOD_AI_OUTPUT
    proposer.handle_event(es2, EVENT)
    proposer.handle_callback(es2, cb(pid, "reject"))
    assert es2.docs[pid]["status"] == "rejected" and not (Path(tmp) / "r").exists()
    print("9 OK  từ chối -> rejected, không ghi file")

    # 10) AI sinh hỏng -> status failed, báo Telegram, không có nút
    es3 = setup(tmp)
    proposer.call_ollama = lambda prompt: "xin loi toi khong biet"
    proposer.handle_event(es3, EVENT)
    assert es3.docs[pid]["status"] == "failed"
    assert "reply_markup" not in sent("sendMessage")[0]
    print("10 OK AI trả rác -> failed, chỉ báo tin, không có nút duyệt")


# ---- Các lỗi chất lượng luật thực tế gặp với phi3:mini (luật nmap trong ảnh Telegram) ----
BAD_FROM_SCREENSHOT = """- rule: Nmap Scanner Spawned In Container
  desc: Động cơ nmap đã được tháp đến trong một chưa, có thể sản xuất chuyên mục điều khiển
  condition: spawned_process and container and proc.name in ("nmap") and proc.cmdline contains ("10.0.0.0/24")
  output: "Nmap Scanner (container=%container.id proc=%proc.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [process, network]
"""
GENERALISED = """- rule: Network Scanner Spawned In Container
  desc: Detects network scanners
  condition: spawned_process and container and proc.name in (nmap, masscan, zmap)
  output: "Scanner (container=%container.id proc=%proc.name cmdline=%proc.cmdline)"
  priority: WARNING
"""
REAL_EVENT = dict(EVENT, output="Network scanner launched (container=abc123def456 proc=nmap cmdline=nmap -sS 10.0.0.0/24)",
                  fields={"proc.name": "nmap", "proc.cmdline": "nmap -sS 10.0.0.0/24"})

with tempfile.TemporaryDirectory() as tmp:
    setup(tmp)
    prompts = []
    answers = iter([BAD_FROM_SCREENSHOT, GENERALISED])
    proposer.call_ollama = lambda prompt: prompts.append(prompt) or next(answers)
    rule, errs = proposer.generate_rule(REAL_EVENT, "pid1")

    # 11) Luật cứng theo IP bị loại ở lần 1, lần 2 được báo lý do và sinh bản tổng quát
    assert rule is not None and "10.0.0.0" not in rule["condition"], rule
    assert "masscan" in rule["condition"]
    assert len(prompts) == 2 and "REJECTED" in prompts[1] and "IP" in prompts[1]
    print("11 OK luật cứng theo 10.0.0.0/24 bị loại, lần 2 nhận phản hồi và ra luật tổng quát")

    # 12) Prompt không để lộ IP / container id thật cho model chép
    assert "10.0.0.0" not in prompts[0] and "abc123def456" not in prompts[0]
    assert "<IP>" in prompts[0] and "<ID>" in prompts[0]
    print("12 OK prompt đã che IP và container id")

    # 13) desc do code tự điền, không giữ câu vô nghĩa của model
    assert "Động cơ" not in rule["desc"] and "Network Scanner Spawned" in rule["desc"] and "nmap" in rule["desc"]
    print("13 OK desc tự điền:", rule["desc"])

    # 14) contains ("x") 1 phần tử được tự sửa, danh sách nhiều phần tử bị loại
    assert proposer.normalize_condition('proc.cmdline contains ("-sS")') == 'proc.cmdline contains "-sS"'
    fixed = proposer.normalize_condition('proc.name in ("nmap") and proc.cmdline contains ("-sS")')
    assert proposer.check_condition(fixed, REAL_EVENT) is None
    multi = proposer.normalize_condition('proc.cmdline contains ("-sS", "-sV")')
    assert "danh sách" in proposer.check_condition(multi, REAL_EVENT)
    print("14 OK contains (\"x\") tự sửa thành contains \"x\"; contains (\"a\",\"b\") bị loại")

    # 15) Model cứ cứng đầu -> hết số lần thử thì trả None (không đưa luật xấu cho người duyệt)
    setup(tmp)
    proposer.call_ollama = lambda prompt: BAD_FROM_SCREENSHOT
    rule, errs = proposer.generate_rule(REAL_EVENT, "pid2")
    assert rule is None and any("IP" in e for e in errs)
    print("15 OK model sinh luật xấu cả 2 lần -> không đưa luật cho người duyệt")


# ---- Luật "chặt" (được phép tự dừng container) và luật "thường" (chỉ cảnh báo) ----
with tempfile.TemporaryDirectory() as tmp:
    setup(tmp)
    S = proposer.is_strict
    # 16) Chỉ lọc theo tên tiến trình -> KHÔNG chặt (dễ dừng nhầm container hợp lệ)
    assert not S("spawned_process and container and proc.name = rm")
    assert not S("spawned_process and container and proc.name in (chmod, chown)")
    assert not S("spawned_process and container and proc.name in (nmap, masscan, zmap)")
    # Tên tiến trình + tham số cụ thể -> chặt
    assert S('spawned_process and container and proc.name = rm and proc.cmdline contains "/var/log/"')
    assert S('spawned_process and container and proc.name = chmod and proc.cmdline contains "u+s"')
    print("16 OK is_strict: chỉ tên tiến trình -> thường; tên tiến trình + tham số -> chặt")

    # 17) `or` ở ngoài ngoặc làm luật rộng ra -> không chặt; tham số quá ngắn -> không chặt
    assert not S('spawned_process and proc.name = rm and proc.cmdline contains "/var/log/" or proc.name = chmod')
    assert S('spawned_process and (proc.name = rm or proc.name = shred) and proc.cmdline contains "/var/log/"')
    assert not S('spawned_process and proc.name = rm and proc.cmdline contains "-f"')
    print("17 OK `or` ngoài ngoặc và tham số quá ngắn -> không chặt")

    # 18) Tên luật có hậu tố -strict chỉ khi chặt
    strict_out = """- rule: Log Wipe
  desc: x
  condition: spawned_process and container and proc.name = rm and proc.cmdline contains "/var/log/"
  output: "Log wipe (container=%container.id cmdline=%proc.cmdline)"
  priority: WARNING
"""
    proposer.call_ollama = lambda prompt: strict_out
    RM_EVENT = dict(EVENT, fields={"proc.name": "rm", "proc.cmdline": "rm -rf /var/log/auth.log /var/log/syslog"})
    r, _ = proposer.generate_rule(RM_EVENT, "pidS")
    assert r["rule"] == "Log Wipe [AI-pidS-strict]", r["rule"]
    proposer.call_ollama = lambda prompt: GOOD_AI_OUTPUT
    r, _ = proposer.generate_rule(EVENT, "pidN")
    assert r["rule"] == "Network Scanner Spawned [AI-pidN]", r["rule"]
    print("18 OK hậu tố -strict chỉ gắn cho luật chặt")

    # 19) Tin Telegram nói rõ luật chặt/thường
    assert "tự động dừng" in proposer.reaction_note({"rule_yaml": "- rule: x [AI-1-strict]"})
    assert "không" in proposer.reaction_note({"rule_yaml": "- rule: x [AI-1]"})
    print("19 OK tin Telegram ghi rõ mức phản ứng")

    # 20) Luật thật AI từng sinh (ảnh Telegram): `or` nằm TRONG ngoặc làm luật khớp mọi lệnh rm/rmdir
    #     của root hoặc mọi tiến trình có "/var/log/" -> KHÔNG được coi là luật chặt
    shot = 'container and (proc.name in (rm, rmdir, rm) or proc.cmdline contains "/var/log/") and user.name = root'
    assert not proposer.is_strict(shot)
    assert not proposer.is_strict('spawned_process and container and proc.name = rm and proc.cmdline contains "/var/log/" or user.name = root')
    assert not proposer.is_strict('container and proc.name = rm and proc.cmdline contains "/var/log/"')  # thiếu spawned_process
    print("20 OK luật có `or` trong ngoặc / thiếu spawned_process không bị coi là luật chặt")


# ---- Luật AI chép ví dụ trong prompt (nmap/masscan) thay vì tiến trình thật (rm) ----
MASSCAN_FOR_RM = """- rule: Masscanned Log Files Deleted
  desc: x
  condition: spawned_process and container and proc.name in (nmap, masscan, zmap) and proc.cmdline contains "/var/log/"
  output: "Logs deleted (container=%container.id proc=%proc.name cmdline=%proc.cmdline)"
  priority: WARNING
"""
RM_RULE = """- rule: Log Files Deleted
  desc: x
  condition: spawned_process and container and proc.name in (rm, rmdir, shred) and proc.cmdline contains "/var/log/"
  output: "Logs deleted (container=%container.id proc=%proc.name cmdline=%proc.cmdline)"
  priority: WARNING
"""
LOG_EVENT = {"container_id": "fff666aaa777", "rule": "System Logs Deleted In Container", "priority": "Warning",
             "output": "System Logs Deleted In Container (container=fff666aaa777 proc=rm cmdline=rm -rf /var/log/auth.log)",
             "fields": {"proc.name": "rm", "proc.cmdline": "rm -rf /var/log/auth.log /var/log/syslog"}}
with tempfile.TemporaryDirectory() as tmp:
    setup(tmp)
    prompts = []
    answers = iter([MASSCAN_FOR_RM, RM_RULE])
    proposer.call_ollama = lambda prompt: prompts.append(prompt) or next(answers)
    rule, errs = proposer.generate_rule(LOG_EVENT, "pid3")
    # 21) Luật liệt kê nmap/masscan cho hành vi `rm` bị loại, lần 2 sinh luật đúng và là luật chặt
    assert rule is not None and "rm" in rule["condition"] and "masscan" not in rule["condition"], rule
    assert len(prompts) == 2 and "observed process 'rm'" in prompts[1]
    assert rule["rule"].endswith("-strict]"), rule["rule"]
    print("21 OK luật chép nmap/masscan cho hành vi rm bị loại; lần 2 ra luật đúng (-strict)")

    # 22) Prompt không còn chứa ví dụ nmap/masscan/zmap để model chép; có nêu tiến trình thật
    assert not any(w in prompts[0].lower() for w in ("nmap", "masscan", "zmap")), "prompt vẫn lộ ví dụ nmap"
    assert "`rm`" in prompts[0]
    print("22 OK prompt không còn ví dụ nmap/masscan/zmap, có nêu tiến trình đã quan sát")

    # 23) Chuỗi cmdline không có trong lệnh thật -> bị loại
    c = 'spawned_process and container and proc.name = rm and proc.cmdline contains "/etc/passwd"'
    assert "does not appear" in proposer.check_condition(c, LOG_EVENT)
    assert proposer.check_condition(
        'spawned_process and container and proc.name in (rm, shred) and proc.cmdline contains "/var/log/"', LOG_EVENT) is None
    print("23 OK chuỗi cmdline không có trong lệnh thật bị loại")


# ---- Luật thứ 3 từ Telegram: `or` nối proc.name với cmdline, cứng theo "rm -rf" ----
THIRD = ('spawned_process and container and (proc.name = rm or proc.name = rmdir or proc.name = rmmod '
         'or proc.cmdline contains "/var/log/") and proc.cmdline contains "-rf" and proc.cmdline contains "rm -rf"')
with tempfile.TemporaryDirectory() as tmp:
    setup(tmp)
    HM = proposer.has_mixed_or
    assert HM(THIRD) and HM('container and (proc.name in (rm) or proc.cmdline contains "/var/log/")')
    assert not HM('spawned_process and (proc.name = rm or proc.name = shred) and proc.cmdline contains "/var/log/"')
    assert not HM('spawned_process and (fd.name startswith "/etc/shadow" or fd.name startswith "/etc/passwd")')
    assert proposer.check_condition(THIRD, LOG_EVENT) and "Use `and`" in proposer.check_condition(THIRD, LOG_EVENT)
    assert not proposer.is_strict(THIRD)
    # 24) Luật có `or` nối proc.name với cmdline bị loại ngay; model được báo cách sửa và thử lại
    third_rule = """- rule: Log Delete
  desc: x
  condition: %s
  output: "x (container=%%container.id proc=%%proc.name cmdline=%%proc.cmdline)"
  priority: WARNING
""" % THIRD
    prompts = []
    answers = iter([third_rule, RM_RULE])
    proposer.call_ollama = lambda prompt: prompts.append(prompt) or next(answers)
    rule, _ = proposer.generate_rule(LOG_EVENT, "pid4")
    assert rule is not None and "or proc.cmdline" not in rule["condition"] and "Use `and`" in prompts[1]
    print("24 OK `or` nối proc.name với cmdline bị loại, model được hướng dẫn dùng `and` và thử lại")

print("\nTẤT CẢ ĐỀU QUA")
