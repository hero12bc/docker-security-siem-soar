"""
ai_rule_generator/proposer.py
Service chạy nền: AI đề xuất luật Falco cho hành vi lạ, người dùng duyệt qua Telegram.

Luồng:
  ai_processor --(topic unknown-threats)--> proposer
    1. Nhờ Ollama sinh 1 luật Falco từ chính sự kiện thật vừa xảy ra.
    2. Kiểm tra cấu trúc luật, lưu vào Elasticsearch (index rule-proposals) trạng thái "pending".
    3. Gửi Telegram kèm 2 nút [Duyệt] [Từ chối].
    4. Bấm Duyệt -> ghi luật ra thư mục chung (RULES_OUT_DIR). Script
       scripts/falco_rule_sync.sh chạy trên máy host sẽ kiểm tra và nạp vào Falco.

Luật KHÔNG BAO GIỜ tự áp dụng khi chưa có người duyệt.
"""

import hashlib
import html
import json
import os
import re
import threading
import time
from pathlib import Path

import requests
import yaml

from generator import call_ollama, validate_falco_rules

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
UNKNOWN_TOPIC = os.getenv("UNKNOWN_TOPIC", "unknown-threats")
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "rule-proposals"
RULES_OUT_DIR = Path(os.getenv("RULES_OUT_DIR", "/rules_out"))

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
# Tùy chọn: danh sách user id Telegram được phép bấm duyệt (cách nhau bởi dấu phẩy).
# Để trống thì ai ở trong đúng TELEGRAM_CHAT_ID cũng bấm được.
APPROVER_IDS = {x.strip() for x in os.getenv("TELEGRAM_APPROVER_IDS", "").split(",") if x.strip()}

ALLOWED_PRIORITIES = {"NOTICE", "WARNING", "ERROR", "CRITICAL"}
# Điều kiện hợp lệ phải có ít nhất 1 phép so sánh cụ thể (tránh luật "bắt mọi thứ").
_OPERATOR_RE = re.compile(r"(\s(=|!=|in|contains|icontains|startswith|endswith|glob|pmatch)\s)", re.I)

# Số lần thử sinh luật (lần sau được báo lý do lần trước bị loại). Mỗi lần mất 1-2 phút.
MAX_ATTEMPTS = int(os.getenv("PROPOSER_MAX_ATTEMPTS", "2"))

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_HEXID_RE = re.compile(r"\b[0-9a-f]{12,64}\b", re.I)
# Các toán tử này chỉ nhận MỘT chuỗi, không nhận danh sách trong ngoặc như `in (...)`.
_SINGLE_OPS = r"(?:contains|icontains|bcontains|startswith|bstartswith|endswith|glob|iglob)"
_ONE_ITEM_LIST_RE = re.compile(
    rf"\b({_SINGLE_OPS})\s*\(\s*(\"[^\"]*\"|'[^']*'|[^\s,()\"']+)\s*\)", re.I)
_ANY_LIST_RE = re.compile(rf"\b{_SINGLE_OPS}\s*\(", re.I)

_decision_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Sinh luật
# --------------------------------------------------------------------------- #
def proposal_id(signature: str) -> str:
    """ID ổn định theo tên luật Falco gốc: cùng 1 hành vi chỉ đề xuất 1 lần."""
    return hashlib.sha1(signature.encode("utf-8")).hexdigest()[:10]


def redact_for_prompt(text: str) -> str:
    """Che địa chỉ IP và ID container trước khi đưa cho AI, để mô hình không chép
    nguyên giá trị cụ thể của lần xảy ra này vào luật (làm luật quá hẹp)."""
    text = _IPV4_RE.sub("<IP>", text)
    return _HEXID_RE.sub("<ID>", text)


def build_prompt(event: dict, feedback: str = "") -> str:
    fields = redact_for_prompt(json.dumps(event.get("fields", {}), ensure_ascii=False))
    output = redact_for_prompt(str(event.get("output")))
    proc_hint = f"`{(event.get('fields') or {}).get('proc.name')}`" if (event.get("fields") or {}).get("proc.name") else "(see fields)"
    retry = (f"\nYour previous attempt was REJECTED because: {feedback}\n"
             "Fix exactly that problem in this attempt.\n") if feedback else ""
    return f"""You are an expert at writing Falco intrusion-detection rules (YAML format).

A container showed suspicious behaviour that none of our existing detection scenarios
covers. This is the real Falco alert that was observed (IP addresses and container ids
are replaced by <IP> and <ID> on purpose):

  falco rule : {event.get('rule')}
  priority   : {event.get('priority')}
  output     : {output}
  fields     : {fields}

Write EXACTLY 1 new Falco rule that detects this TYPE of behaviour in general, not only
this single occurrence.

Requirements:
- Use only standard Falco fields and macros: spawned_process, container, proc.name,
  proc.cmdline, proc.pname, fd.name, evt.type, user.name, container.image.repository.
- Generalise. Do NOT hard-code IP addresses, ports, container ids, container names or the
  exact command line that was observed. Match the tool by process name: the observed
  process {proc_hint} plus a few common alternatives of the same kind.
- The condition must still be specific enough not to match all container activity.
- `contains`, `startswith` and `endswith` take ONE quoted string, for example
  proc.cmdline contains "-sS". Never write contains ("a", "b"). Use `in (...)` for lists.
- Start the condition with spawned_process, e.g. spawned_process and container and ...
- If the tool is also used legitimately (rm, chmod, cp, sh ...), do not match on proc.name alone:
  also require a generic dangerous argument, e.g. proc.name = rm and proc.cmdline contains "/var/log/".
- The output must include %container.id, %proc.name and %proc.cmdline.
- priority must be WARNING or CRITICAL.
- desc: one short English sentence.

- The rule MUST fire for the observed alert above: its proc.name must include the observed
  process and any proc.cmdline text you require must really appear in the observed command line.

Format example (structure only; replace TOOL_A, TOOL_B and ARGUMENT with real values taken
from the alert above, never copy the placeholders):
- rule: Example Suspicious Tool Spawned
  desc: Detects a suspicious tool being run inside a container
  condition: spawned_process and container and proc.name in (TOOL_A, TOOL_B) and proc.cmdline contains "ARGUMENT"
  output: "Suspicious tool (container=%container.id proc=%proc.name cmdline=%proc.cmdline)"
  priority: WARNING
  tags: [process]
{retry}
Return ONLY a raw YAML list starting with "- rule:". No explanation before or after.
"""


def is_specific(condition: str) -> bool:
    return bool(_OPERATOR_RE.search(f" {condition} "))


_PROC_CLAUSE_RE = re.compile(r"\bproc\.name\s+(=|in)\s")
_ARG_CLAUSE_RE = re.compile(
    r"\b(proc\.cmdline|proc\.args|fd\.name)\s+(contains|icontains|startswith|endswith|=)\s+[\"']([^\"']{3,})[\"']",
    re.I)
STRICT_SUFFIX = "-strict"


def _split_top(text: str, word: str):
    """Tách `text` theo từ khóa and/or CHỈ ở độ sâu ngoặc 0. Trả về (các phần, đủ ngoặc cân bằng)."""
    parts, depth, last = [], 0, 0
    for m in re.finditer(r"\(|\)|\b" + word + r"\b", text, re.I):
        t = m.group(0)
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
        elif depth == 0:
            parts.append(text[last:m.start()].strip())
            last = m.end()
    parts.append(text[last:].strip())
    return parts


def _strip_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")") and len(_split_top(text[1:-1], "and")) >= 1:
        inner, depth, ok = text[1:-1], 0, True
        for ch in inner:
            depth += (ch == "(") - (ch == ")")
            if depth < 0:
                ok = False
                break
        if not ok or depth != 0:
            break
        text = inner.strip()
    return text


def _or_groups(condition: str):
    """Trả về danh sách các nhóm toán hạng nối bằng `or` (trong từng cặp ngoặc và ở mức ngoài cùng)."""
    group = re.compile(r"\(([^()]*)\)")
    out, top = [], condition
    while True:
        for m in group.finditer(top):
            parts = re.split(r"\bor\b", m.group(1), flags=re.I)
            if len(parts) > 1:
                out.append(parts)
        new_top = group.sub(" X ", top)
        if new_top == top:
            break
        top = new_top
    parts = re.split(r"\bor\b", top, flags=re.I)
    if len(parts) > 1:
        out.append(parts)
    return out


def _is_proc_clause(text: str) -> bool:
    return bool(re.match(r"\s*proc\.name\s+(=|in)\s", text))


def has_mixed_or(condition: str) -> bool:
    """`or` nối tên tiến trình với điều kiện khác (vd. proc.name = rm or proc.cmdline contains "x")
    làm luật khớp RỘNG hơn nhiều so với ý định: chỉ cần một vế đúng là nổ."""
    for parts in _or_groups(condition):
        flags = [_is_proc_clause(p) for p in parts]
        if any(flags) and not all(flags):
            return True
    return False


def is_strict(condition: str) -> bool:
    """Luật 'chặt' = đủ cụ thể để được phép lên CRITICAL (tự dừng container) sau khi người duyệt.
    Điều kiện:
      1. có CẢ tên tiến trình (proc.name = / in) lẫn một tham số/đường dẫn cụ thể (>= 3 ký tự);
      2. gắn với sự kiện chạy tiến trình (spawned_process hoặc evt.type), không áp cho mọi syscall;
      3. `or` chỉ được nối các điều kiện proc.name với nhau, vd (proc.name = rm or proc.name = shred).
    Luật chỉ lọc theo tên tiến trình (rm, chmod...) quá dễ dừng nhầm container hợp lệ."""
    if not (_PROC_CLAUSE_RE.search(condition) and _ARG_CLAUSE_RE.search(condition)):
        return False
    if not re.search(r"\bspawned_process\b|\bevt\.type\s*(=|in)\s", condition):
        return False
    return all(all(_is_proc_clause(p) for p in parts) for parts in _or_groups(condition))


def normalize_condition(condition: str) -> str:
    """Sửa lỗi cú pháp phổ biến của model nhỏ: contains ("x") -> contains "x"."""
    return _ONE_ITEM_LIST_RE.sub(lambda m: f"{m.group(1)} {m.group(2)}", condition)


_PROCNAME_VALUES_RE = re.compile(r"\bproc\.name\s+(?:=\s*([^\s()]+)|in\s*\(([^)]*)\))", re.I)
_CMDLINE_LIT_RE = re.compile(
    r"\bproc\.cmdline\s+(?:contains|icontains|startswith|endswith|=)\s+[\"']([^\"']+)[\"']", re.I)


def check_covers_event(condition: str, event: dict):
    """Luật phải nổ được với chính hành vi đã quan sát. Model nhỏ hay chép ví dụ trong prompt
    (vd. nmap) thay vì dùng tiến trình thật (vd. rm) -> luật vô dụng nhưng trông hợp lệ."""
    fields = event.get("fields") or {}
    proc = str(fields.get("proc.name") or "").strip().lower()
    if proc:
        names = set()
        for m in _PROCNAME_VALUES_RE.finditer(condition):
            raw = m.group(1) if m.group(1) is not None else m.group(2)
            names |= {x.strip().strip("\"'").lower() for x in raw.split(",") if x.strip()}
        if names and proc not in names:
            return (f"condition must match the observed process '{proc}' in proc.name "
                    f"(it only lists: {', '.join(sorted(names))}); do not copy names from the example")
    cmd = str(fields.get("proc.cmdline") or "").lower()
    if cmd:
        for lit in _CMDLINE_LIT_RE.findall(condition):
            if lit.lower() not in cmd:
                return (f'proc.cmdline text "{lit}" does not appear in the observed command line, '
                        "so the rule would not fire for the observed alert")
    return None


def check_condition(condition: str, event: dict):
    """Trả về mô tả lỗi nếu điều kiện không đạt, None nếu đạt."""
    if not is_specific(condition):
        return "condition quá chung chung (thiếu phép so sánh cụ thể)"
    if _ANY_LIST_RE.search(condition):
        return ("contains/startswith/endswith chỉ nhận MỘT chuỗi, không nhận danh sách "
                "trong ngoặc; dùng `in (...)` cho danh sách")
    if _IPV4_RE.search(condition):
        return "condition không được cứng nhắc theo địa chỉ IP, phải tổng quát hóa"
    cid = str(event.get("container_id", ""))
    if _HEXID_RE.search(condition) or (cid and cid[:12] in condition):
        return "condition không được chứa ID container"
    if has_mixed_or(condition):
        return ("do not join proc.name and other conditions with `or`: a rule like "
                "(proc.name = X or proc.cmdline contains \"Y\") fires when EITHER is true. "
                "Use `and` between the process name and the argument; use `or` only between several proc.name values")
    return check_covers_event(condition, event)


def finalize_rule(rule: dict, pid: str, event: dict = None) -> dict:
    """Chuẩn hóa luật AI sinh ra trước khi đưa cho người duyệt."""
    rule = dict(rule)
    event = event or {}
    # Hậu tố [AI-<id>] để ai_processor nhận diện và để tránh trùng tên luật có sẵn.
    # Luật 'chặt' có thêm "-strict": sau khi được duyệt, ai_processor cho phép lên CRITICAL.
    strict = is_strict(str(rule.get("condition", "")))
    rule["rule"] = f"{str(rule['rule']).strip()} [AI-{pid}{STRICT_SUFFIX if strict else ''}]"

    # Mô tả do code tự điền, KHÔNG tin model: model nhỏ viết tiếng Việt thành câu vô nghĩa.
    proc = (event.get("fields") or {}).get("proc.name")
    rule["desc"] = (f"Luật do AI đề xuất từ cảnh báo Falco '{event.get('rule', '?')}'"
                    + (f" (tiến trình: {proc})" if proc else "")
                    + ". Cần người duyệt trước khi áp dụng.")

    # Luật AI chưa được kiểm chứng nên luôn để WARNING, không để model tự nâng lên CRITICAL.
    rule["priority"] = "WARNING"

    # Falco chỉ đưa container.id vào output_fields khi output có nhắc tới nó.
    # Thiếu thì ai_processor không biết luật nổ ở container nào.
    output = str(rule["output"])
    if "%container.id" not in output:
        output = f"{output} (container=%container.id)"
    rule["output"] = output

    tags = rule.get("tags")
    tags = list(tags) if isinstance(tags, list) else []
    if "ai_generated" not in tags:
        tags.append("ai_generated")
    rule["tags"] = tags
    return rule


def generate_rule(event: dict, pid: str):
    """Trả về (rule_dict | None, danh_sách_lỗi). Thử tối đa MAX_ATTEMPTS lần,
    lần sau được báo lý do lần trước bị loại."""
    all_errors, feedback = [], ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        raw = call_ollama(build_prompt(event, feedback))
        valid, errors = validate_falco_rules(raw)
        all_errors += errors
        rejected = []
        for r in valid:
            r = dict(r)
            r["condition"] = normalize_condition(str(r.get("condition", "")))
            problem = check_condition(r["condition"], event)
            if problem is None:
                return finalize_rule(r, pid, event), all_errors
            rejected.append(problem)
            all_errors.append(f"Luật '{r.get('rule')}' bị loại: {problem}")
        feedback = "; ".join(rejected) or "; ".join(errors) or \
            "the output was not a valid YAML list of Falco rules"
        print(f"[proposer] Lần {attempt}/{MAX_ATTEMPTS} bị loại: {feedback}")
    return None, all_errors


# --------------------------------------------------------------------------- #
# Telegram
# --------------------------------------------------------------------------- #
def tg(method: str, **payload) -> dict:
    resp = requests.post(
        f"https://api.telegram.org/bot{TOKEN}/{method}", json=payload, timeout=40
    )
    resp.raise_for_status()
    return resp.json()


def reaction_note(doc: dict) -> str:
    if f"{STRICT_SUFFIX}]" in str(doc.get("rule_yaml", "")):
        return ("⚠️ <b>Luật CHẶT</b>: sau khi duyệt, nếu luật này nổ thì hệ thống "
                "có thể <b>tự động dừng container</b>. Hãy đọc kỹ condition.")
    return ("ℹ️ <b>Luật thường</b>: sau khi duyệt chỉ cảnh báo (mức HIGH), "
            "<b>không</b> tự động dừng container.")


def format_proposal(doc: dict) -> str:
    ev = doc["event"]
    yaml_text = doc["rule_yaml"]
    if len(yaml_text) > 2500:
        yaml_text = yaml_text[:2500] + "\n..."
    return (
        "🧠 <b>AI đề xuất luật Falco mới</b>\n"
        f"Hành vi lạ: <code>{html.escape(str(ev.get('rule')))}</code> "
        f"({html.escape(str(ev.get('priority')))})\n"
        f"Container: <code>{html.escape(str(ev.get('container_id')))}</code>\n"
        f"Falco báo: <code>{html.escape(str(ev.get('output'))[:400])}</code>\n\n"
        f"<b>Luật đề xuất:</b>\n<pre>{html.escape(yaml_text)}</pre>\n"
        f"{reaction_note(doc)}\n"
        "Duyệt để luật được nạp vào Falco, hoặc từ chối để bỏ qua."
    )


def send_proposal(pid: str, doc: dict) -> None:
    if not (TOKEN and CHAT_ID):
        print("[proposer] Thiếu TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID, không gửi được Telegram.")
        return
    tg(
        "sendMessage",
        chat_id=CHAT_ID,
        text=format_proposal(doc),
        parse_mode="HTML",
        reply_markup={"inline_keyboard": [[
            {"text": "✅ Duyệt", "callback_data": f"approve:{pid}"},
            {"text": "❌ Từ chối", "callback_data": f"reject:{pid}"},
        ]]},
    )


def notify_text(text: str) -> None:
    if TOKEN and CHAT_ID:
        try:
            tg("sendMessage", chat_id=CHAT_ID, text=text)
        except Exception as e:
            print(f"[proposer] Gửi Telegram lỗi: {e}")


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------- #
# Xử lý 1 hành vi lạ
# --------------------------------------------------------------------------- #
def handle_event(es, event: dict) -> None:
    signature = str(event.get("rule", "")).strip()
    if not signature:
        return
    pid = proposal_id(signature)

    if es.exists(index=ES_INDEX, id=pid):
        print(f"[proposer] '{signature}' đã từng được xử lý ({pid}), bỏ qua.")
        return

    print(f"[proposer] Hành vi lạ '{signature}' -> nhờ AI sinh luật (có thể mất 1-2 phút)...")
    rule, errors = generate_rule(event, pid)

    if rule is None:
        es.index(index=ES_INDEX, id=pid, refresh=True, document={
            "status": "failed", "signature": signature, "event": event,
            "errors": errors, "created_at": now_utc(),
        })
        print(f"[proposer] AI không sinh được luật hợp lệ cho '{signature}': {errors}")
        notify_text(f"⚠️ AI không sinh được luật hợp lệ cho hành vi '{signature}'. "
                    "Cần xem tay (chi tiết trong index rule-proposals).")
        return

    doc = {
        "status": "pending",
        "signature": signature,
        "event": event,
        "rule_yaml": yaml.safe_dump([rule], allow_unicode=True, sort_keys=False),
        "created_at": now_utc(),
    }
    es.index(index=ES_INDEX, id=pid, document=doc, refresh=True)
    print(f"[proposer] Đã lưu đề xuất {pid} (pending), gửi Telegram để duyệt.")
    send_proposal(pid, doc)


# --------------------------------------------------------------------------- #
# Xử lý bấm nút Duyệt / Từ chối
# --------------------------------------------------------------------------- #
def is_authorized(cb: dict) -> bool:
    chat_id = str(cb.get("message", {}).get("chat", {}).get("id", ""))
    if not CHAT_ID or chat_id != str(CHAT_ID):
        return False
    if APPROVER_IDS and str(cb.get("from", {}).get("id", "")) not in APPROVER_IDS:
        return False
    return True


def write_approved_rule(pid: str, rule_yaml: str) -> Path:
    RULES_OUT_DIR.mkdir(parents=True, exist_ok=True)
    final = RULES_OUT_DIR / f"ai-{pid}.yaml"
    tmp = RULES_OUT_DIR / f"ai-{pid}.yaml.tmp"  # script sync bỏ qua *.tmp
    tmp.write_text(rule_yaml, encoding="utf-8")
    os.replace(tmp, final)
    return final


def handle_callback(es, cb: dict) -> None:
    cb_id = cb.get("id")
    data = str(cb.get("data", ""))

    if not is_authorized(cb):
        print(f"[proposer] Bỏ qua callback từ nguồn không được phép: {cb.get('from')}")
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Bạn không có quyền duyệt.", show_alert=True)
        return

    action, _, pid = data.partition(":")
    if action not in ("approve", "reject") or not pid:
        tg("answerCallbackQuery", callback_query_id=cb_id, text="Lệnh không hợp lệ.")
        return

    with _decision_lock:  # tránh bấm 2 lần cùng lúc
        try:
            doc = es.get(index=ES_INDEX, id=pid)["_source"]
        except Exception:
            tg("answerCallbackQuery", callback_query_id=cb_id, text="Không tìm thấy đề xuất này.", show_alert=True)
            return

        if doc.get("status") != "pending":
            tg("answerCallbackQuery", callback_query_id=cb_id,
               text=f"Đề xuất này đã được xử lý ({doc.get('status')}).", show_alert=True)
            return

        who = (cb.get("from") or {}).get("username") or str((cb.get("from") or {}).get("id"))
        if action == "approve":
            try:
                path = write_approved_rule(pid, doc["rule_yaml"])
            except Exception as e:
                tg("answerCallbackQuery", callback_query_id=cb_id, text=f"Lỗi ghi luật: {e}", show_alert=True)
                return
            status = "approved"
            reply = (f"✅ Đã duyệt luật {pid}. File: {path.name}.\n"
                     "Luật sẽ vào Falco khi script falco_rule_sync.sh trên máy host chạy.")
        else:
            status = "rejected"
            reply = f"❌ Đã từ chối luật {pid}. Luật sẽ không được dùng."

        es.update(index=ES_INDEX, id=pid, refresh=True,
                  doc={"status": status, "decided_by": who, "decided_at": now_utc()})

    print(f"[proposer] {pid} -> {status} (bởi {who})")
    tg("answerCallbackQuery", callback_query_id=cb_id, text=status)
    msg = cb.get("message", {})
    try:
        tg("editMessageReplyMarkup", chat_id=msg["chat"]["id"], message_id=msg["message_id"],
           reply_markup={"inline_keyboard": []})
    except Exception:
        pass
    notify_text(reply)


def poll_telegram(es) -> None:
    offset = None
    print("[proposer] Bắt đầu lắng nghe nút Duyệt/Từ chối trên Telegram.")
    while True:
        try:
            params = {"timeout": 25, "allowed_updates": ["callback_query"]}
            if offset is not None:
                params["offset"] = offset
            result = tg("getUpdates", **params).get("result", [])
            for upd in result:
                offset = upd["update_id"] + 1
                if "callback_query" in upd:
                    try:
                        handle_callback(es, upd["callback_query"])
                    except Exception as e:
                        print(f"[proposer] Lỗi xử lý callback: {e}")
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            print(f"[proposer] getUpdates lỗi HTTP {code} (409 nghĩa là bot đang có webhook "
                  "hoặc có tiến trình khác đang getUpdates cùng token).")
            time.sleep(10)
        except Exception as e:
            print(f"[proposer] getUpdates lỗi: {e}")
            time.sleep(5)


# --------------------------------------------------------------------------- #
def main() -> None:
    from elasticsearch import Elasticsearch
    from kafka import KafkaConsumer

    es = Elasticsearch(ES_HOST)

    if TOKEN and CHAT_ID:
        threading.Thread(target=poll_telegram, args=(es,), daemon=True).start()
    else:
        print("[proposer] CẢNH BÁO: thiếu TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID, "
              "đề xuất sẽ chỉ được lưu vào Elasticsearch, không duyệt được qua Telegram.")

    consumer = None
    while consumer is None:
        try:
            consumer = KafkaConsumer(
                UNKNOWN_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_deserializer=lambda v: json.loads(v.decode("utf-8", errors="ignore")),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                group_id="rule-proposer-v1",
                api_version=(3, 7, 0),
            )
        except Exception as e:
            print(f"[proposer] Đang chờ Kafka sẵn sàng... ({e})")
            time.sleep(3)

    print(f"[proposer] Đang lắng nghe topic '{UNKNOWN_TOPIC}' (bootstrap={KAFKA_BOOTSTRAP})")
    for msg in consumer:
        if not isinstance(msg.value, dict):
            continue
        try:
            handle_event(es, msg.value)
        except Exception as e:
            print(f"[proposer] Lỗi xử lý sự kiện: {e}")


if __name__ == "__main__":
    main()
