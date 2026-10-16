#!/usr/bin/env bash
# scripts/falco_rule_sync.sh
#
# Chạy trên MÁY HOST (cần root vì ghi vào /etc/falco và reload Falco).
# Theo dõi thư mục falco_rules_approved/ (nơi service rule_proposer ghi luật đã được
# duyệt trên Telegram), rồi với mỗi luật mới:
#   1. Kiểm tra bằng `falco -V` (cùng bộ luật chính để macro như spawned_process dùng được).
#   2. Chép vào thư mục rules.d của Falco.
#   3. Nạp lại Falco. Nếu Falco không chạy được sau đó thì GỠ luật vừa thêm và nạp lại.
#
# Cách dùng:
#   sudo ./scripts/falco_rule_sync.sh          # chạy liên tục, quét mỗi 10 giây
#   sudo ./scripts/falco_rule_sync.sh --once   # quét một lần rồi thoát
#
# Biến môi trường (đều có giá trị mặc định, đổi nếu Falco của bạn cài khác):
#   SRC_DIR            thư mục luật đã duyệt          (mặc định: <repo>/falco_rules_approved)
#   FALCO_RULES_DIR    thư mục rules.d của Falco       (mặc định: /etc/falco/rules.d)
#   FALCO_MAIN_RULES   file luật chính của Falco       (mặc định: /etc/falco/falco_rules.yaml)
#   FALCO_CONFIG       file cấu hình falco.yaml        (mặc định: /etc/falco/falco.yaml)
#   FALCO_BIN          lệnh falco                      (mặc định: falco)
#   FALCO_SERVICE      tên service systemd             (mặc định: falco)
#   RELOAD_CMD         lệnh nạp lại Falco              (mặc định: systemctl restart $FALCO_SERVICE)
#   HEALTH_CMD         lệnh kiểm tra Falco đang chạy   (mặc định: systemctl is-active --quiet $FALCO_SERVICE)
#   INTERVAL           giây giữa 2 lần quét            (mặc định: 10)
#   SETTLE             giây chờ sau reload trước khi kiểm tra sức khỏe (mặc định: 3)
#   SKIP_VALIDATE=1    bỏ qua bước falco -V (KHÔNG khuyến khích)

set -u
shopt -s nullglob

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SRC_DIR:-$HERE/../falco_rules_approved}"
DEST_DIR="${FALCO_RULES_DIR:-/etc/falco/rules.d}"
FALCO_MAIN_RULES="${FALCO_MAIN_RULES:-/etc/falco/falco_rules.yaml}"
FALCO_CONFIG="${FALCO_CONFIG:-/etc/falco/falco.yaml}"
FALCO_BIN="${FALCO_BIN:-falco}"
FALCO_SERVICE="${FALCO_SERVICE:-falco}"
RELOAD_CMD="${RELOAD_CMD:-systemctl restart $FALCO_SERVICE}"
HEALTH_CMD="${HEALTH_CMD:-systemctl is-active --quiet $FALCO_SERVICE}"
INTERVAL="${INTERVAL:-10}"
SETTLE="${SETTLE:-3}"
SKIP_VALIDATE="${SKIP_VALIDATE:-0}"

log() { echo "[$(date '+%F %T')] $*"; }

validate() {
  [ "$SKIP_VALIDATE" = "1" ] && return 0
  "$FALCO_BIN" -V "$FALCO_MAIN_RULES" -V "$1" >/dev/null 2>&1
}

sync_once() {
  local installed=() f name dest

  for f in "$SRC_DIR"/ai-*.yaml; do
    name="$(basename "$f")"
    dest="$DEST_DIR/$name"

    # Đã nạp rồi (nội dung giống hệt) thì bỏ qua.
    if [ -f "$dest" ] && cmp -s "$f" "$dest"; then
      continue
    fi

    if ! validate "$f"; then
      log "LUẬT KHÔNG HỢP LỆ theo falco -V: $name -> đổi tên thành $name.invalid, KHÔNG nạp."
      mv -f "$f" "$f.invalid"
      continue
    fi

    mkdir -p "$DEST_DIR"
    install -m 0644 "$f" "$dest"
    installed+=("$name")
    log "Đã chép luật $name vào $DEST_DIR"
  done

  [ "${#installed[@]}" -eq 0 ] && return 0

  log "Nạp lại Falco: $RELOAD_CMD"
  bash -c "$RELOAD_CMD"
  sleep "$SETTLE"

  if bash -c "$HEALTH_CMD"; then
    log "Falco hoạt động bình thường, đã áp dụng ${#installed[@]} luật mới: ${installed[*]}"
    return 0
  fi

  log "!!! Falco KHÔNG chạy sau khi nạp luật mới. Đang GỠ các luật vừa thêm và nạp lại."
  for name in "${installed[@]}"; do
    rm -f "$DEST_DIR/$name"
    mv -f "$SRC_DIR/$name" "$SRC_DIR/$name.failed"
  done
  bash -c "$RELOAD_CMD"
  sleep "$SETTLE"
  if bash -c "$HEALTH_CMD"; then
    log "Đã khôi phục: Falco chạy lại bình thường. Các luật lỗi đổi tên thành *.failed trong $SRC_DIR"
  else
    log "!!! Falco vẫn không chạy sau khi gỡ luật. Cần kiểm tra thủ công: journalctl -u $FALCO_SERVICE"
  fi
  return 1
}

# ---- Kiểm tra môi trường khi khởi động ----
if [ "$SKIP_VALIDATE" != "1" ] && ! command -v "$FALCO_BIN" >/dev/null 2>&1; then
  echo "Không tìm thấy lệnh '$FALCO_BIN'. Nếu Falco chạy trong Docker hoặc ở đường dẫn khác,"
  echo "đặt FALCO_BIN=... (hoặc SKIP_VALIDATE=1 nếu chấp nhận nạp luật mà không kiểm tra)." >&2
  exit 1
fi
if [ -f "$FALCO_CONFIG" ] && ! grep -q "$DEST_DIR" "$FALCO_CONFIG"; then
  log "CẢNH BÁO: $FALCO_CONFIG không nhắc tới $DEST_DIR trong rules_files, Falco có thể không đọc thư mục này."
fi
mkdir -p "$SRC_DIR"

log "Theo dõi $SRC_DIR -> $DEST_DIR (quét mỗi ${INTERVAL}s)"
if [ "${1:-}" = "--once" ]; then
  sync_once
  exit $?
fi
while true; do
  sync_once
  sleep "$INTERVAL"
done
