# Docker Security SIEM/SOAR Platform

Hệ thống giám sát an ninh container với AI phát hiện & tự động xử lý.

## 🎯 Tính năng

- ✅ Real-time monitoring (CPU, RAM, Logs, Syscalls)
- ✅ AI Correlation Engine
- ✅ Risk Scoring (1-100)
- ✅ Automated Response (SOAR)
- ✅ Auto Rule Generation (Ollama)
- ✅ Telegram Alerts

## 📋 Yêu cầu

- Docker Desktop v4.10+ hoặc Docker Engine
- WSL2 (Windows) / Linux / macOS
- RAM ≥ 16GB
- Disk ≥ 50GB

## 🚀 Cài Đặt Nhanh

> ⚠️ **Lưu ý bắt buộc trước khi chạy `docker compose up`:** đổi quyền sở hữu 2 file cấu hình sau về `root`, nếu không `filebeat` và `metricbeat` sẽ crash ngay khi khởi động (Elastic Beats từ chối nạp config không thuộc sở hữu root vì lý do bảo mật):
> ```bash
> sudo chown root:root configs/filebeat.yml configs/metricbeat.yml
> sudo chmod go-w configs/filebeat.yml configs/metricbeat.yml
> ```
> Nếu quên bước này, log của 2 service sẽ hiện lỗi dạng `Exiting: error loading config file (...) must be owned by the user identifier (uid=0) or root`, khiến toàn bộ tín hiệu log/CPU không bao giờ tới được `ai_processor` dù mã nguồn xử lý hoàn toàn đúng.

### 1. Khởi chạy hệ thống
```bash
git clone [https://github.com/hero12bc/docker-security-siem-soar.git](https://github.com/hero12bc/docker-security-siem-soar.git)
cd docker-security-siem-soar

# Cấu hình biến môi trường
cp .env.example .env
# Chỉnh sửa TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID trong .env

# Khởi chạy toàn bộ services
docker compose up -d --build

2. Truy cập & Cấu hình Grafana
Mở trình duyệt truy cập: http://localhost:3000

Đăng nhập mặc định:

User: admin

Password: admin (Hệ thống sẽ yêu cầu đổi pass lần đầu, có thể chọn Skip)

Import Dashboard có sẵn:

> ⚠️ Nếu đây là lần đầu chạy trên volume mới (hoặc từng chạy `docker compose down -v`), Grafana sẽ **chưa có data source Elasticsearch nào cả** — phải tạo lại trước khi import dashboard, nếu không dashboard sẽ hiện "No data" ở mọi panel dù import thành công. Vào **Connections > Data sources > Add new connection > Elasticsearch**, điền URL `http://elasticsearch:9200` (dùng tên service Docker, không dùng `localhost`) và Index name `security-incidents`, bấm **Save & Test**.

Tại menu bên trái, chọn Dashboards -> Bấm nút New (góc trên bên phải) -> Chọn Import.

Bấm Upload dashboard JSON file.

Chọn file `Thongkemaucanhbaoanninh.json` ở thư mục gốc của project.

Bấm Import để hoàn tất. Nếu panel vẫn "No data" sau khi có data source, vào Edit từng panel và chọn lại đúng data source vừa tạo (dashboard export cũ có thể còn trỏ tới UID data source cũ đã không còn tồn tại).

3. Chạy Kịch Bản Kiểm Thử (Attack Simulation)

# 1. Tạo container nạn nhân
1.Xóa container test cũ:Ngay lập tức.Xóa container victim hiện tại:Bashdocker rm -f victim_container 2>/dev/null; echo ok
Cách xác minh: Terminal xuất ra ok.
# 2. Kích hoạt kịch bản đào coin
2.Tạo container nạn nhân mới (giả lập đào coin):Ngay lập tức.Chạy lệnh tạo container victim thực hiện tải CPU và tạo log mining:Bashset +H; docker run -d --name victim_container alpine sh -c "printf '#!/bin/sh\ncat /etc/shadow > /dev/null\nsleep 3600\n' > /tmp/xmrig; chmod +x /tmp/xmrig; echo 'connecting to pool stratum+tcp://xmrig.pool.minexmr.com:4444'; yes > /dev/null & /tmp/xmrig"
Cách xác minh: Terminal trả về ID đầy đủ của container mới vừa khởi chạy.3.Quan sát log của ai_processor:Theo dõi 90 giây.Xem log trực tiếp để kiểm tra chỉ số age_cpu:Bashdocker compose logs -f --tail=0 ai_processor
Cách xác minh: Quan sát các dòng [DEBUG-AGE]. Chỉ số age_cpu bắt đầu cập nhật về dạng 0.0s, 10.0s... (thay vì cố định -1.0s) và cảnh báo đẩy lên mức CRITICAL (score = 100).

## 🧠 AI tự đề xuất luật cho hành vi lạ (duyệt qua Telegram)

Khi trong container xuất hiện hành vi mà **chưa kịch bản nào trong `ai_processor/scenarios.py` bao phủ**, hệ thống nhờ AI đề xuất luật Falco mới và hỏi bạn trên Telegram. Luật **không bao giờ tự áp dụng** khi chưa có người bấm Duyệt.

```
Falco ──> connector ──> Kafka (docker-syscalls) ──> ai_processor
                                                        │ alert Falco (>= Warning) không khớp kịch bản nào
                                                        ▼
                                              Kafka (unknown-threats)
                                                        ▼
                                  rule_proposer ── Ollama sinh luật ── kiểm tra cấu trúc
                                                        │ lưu Elasticsearch (rule-proposals, status=pending)
                                                        ▼
                                  Telegram: [✅ Duyệt] [❌ Từ chối]
                                                        │ bấm Duyệt
                                                        ▼
                                  falco_rules_approved/ai-<id>.yaml
                                                        ▼
                    scripts/falco_rule_sync.sh (chạy trên máy host)
                    falco -V kiểm tra → chép vào /etc/falco/rules.d → reload Falco
```

### Cài đặt

```bash
# 1. Build lại 2 service bị thay đổi và bật service mới
docker compose up -d --build ai_processor rule_proposer

# 2. Đảm bảo Ollama đã có model (lệnh này phải chạy lại nếu từng `docker compose down -v`)
docker exec -it siem-ollama ollama pull phi3:mini

# 3. Trên MÁY HOST, chạy script nạp luật đã duyệt vào Falco (cần root)
sudo ./scripts/falco_rule_sync.sh
```

Script tự kiểm tra từng luật bằng `falco -V`, chép vào `/etc/falco/rules.d`, reload Falco, và **gỡ luật vừa thêm nếu Falco không chạy được sau đó**. Nếu Falco của bạn cài khác mặc định (tên service, đường dẫn), đặt các biến môi trường `FALCO_SERVICE`, `FALCO_RULES_DIR`, `FALCO_MAIN_RULES`, `RELOAD_CMD`, `HEALTH_CMD` (xem phần đầu file script). Falco phải đọc thư mục `rules.d` trong `rules_files` của `falco.yaml`.

### Chạy thử

```bash
pip3 install kafka-python --break-system-packages
python3 test_simulate_unknown.py list     # xem các tình huống zero-day giả lập
python3 test_simulate_unknown.py scan     # chạy 1 tình huống: scan | escape | setuid | logwipe | cron
python3 test_simulate_unknown.py all      # gửi cả 5 (rule_proposer xử lý lần lượt, mỗi luật 1-2 phút)
docker compose logs -f ai_processor     # kỳ vọng dòng [UNKNOWN-THREAT]
docker compose logs -f rule_proposer    # AI sinh luật, mất khoảng 1-2 phút
```

Sau đó Telegram nhận tin "AI đề xuất luật Falco mới" kèm hai nút. Bấm **Duyệt** thì file `falco_rules_approved/ai-<id>.yaml` được tạo và script trên host sẽ nạp vào Falco trong vòng 10 giây.

### Chạy lại cùng một tình huống

Mỗi tên luật chỉ được đề xuất một lần, nên muốn chạy lại cần xóa đề xuất cũ. Trước hết kiểm tra đã có đề xuất nào chưa (chạy trên máy host):

```bash
curl -s "localhost:9200/rule-proposals/_search?size=50&filter_path=hits.hits._id,hits.hits._source.status,hits.hits._source.event.rule&pretty"
```

Kết quả cho biết `_id`, `status` (`pending`, `approved`, `rejected`, `failed`) và tên hành vi lạ. Nếu index chưa tồn tại (`index_not_found`) nghĩa là chưa có đề xuất nào. Sau đó xóa:

```bash
curl -X DELETE "localhost:9200/rule-proposals/_doc/<id>"                      # xóa một đề xuất
curl -X POST "localhost:9200/rule-proposals/_delete_by_query?refresh=true" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'          # xóa tất cả
docker compose restart ai_processor   # xóa bộ nhớ chống trùng 1 giờ của ai_processor
```

Xóa đề xuất trong Elasticsearch **không** gỡ luật đã duyệt khỏi Falco. Muốn gỡ, xóa file `ai-<id>.yaml` trong `falco_rules_approved/` và `/etc/falco/rules.d/`.

### Hệ thống chặn được đến đâu

| Tình huống | Kết quả |
|---|---|
| Kịch bản có sẵn (đào coin, reverse shell, ...) đủ tín hiệu | Phát hiện và tự dừng container, báo Telegram |
| Zero-day xảy ra lần đầu | Chỉ phát hiện, AI đề xuất luật. Tấn công lần đó **chưa bị chặn** |
| Zero-day lặp lại sau khi duyệt luật thường | Cảnh báo HIGH, **không** tự dừng container |
| Zero-day lặp lại sau khi duyệt luật chặt (`-strict`) | Chấm CRITICAL, có thể tự dừng container |

Luật Falco bản thân chỉ phát hiện. Việc dừng container do `incident_responder` thực hiện khi sự cố đạt CRITICAL. Luật AI luôn có `priority: WARNING` do code ép, model không được tự nâng lên CRITICAL.

Vì sao luật chỉ lọc theo tên tiến trình không được phép chặn: các lệnh như `rm`, `chmod` được nhiều ứng dụng hợp lệ dùng (dọn file tạm, phân quyền khi khởi động), nên luật `proc.name = rm` sẽ dừng nhầm container bình thường. Chỉ cách dùng đáng ngờ (`rm` kèm `/var/log/`, `chmod` kèm `u+s`) mới đủ cụ thể.

Không cần train hay fine-tune model. Chất lượng luật được kiểm soát bằng prompt (che IP và container id, yêu cầu tổng quát hóa), bộ kiểm tra condition bằng code, thử lại tối đa 2 lần, `falco -V` và người duyệt.

### Những điều cần biết

- Chỉ Falco alert có priority từ **Warning** trở lên, xảy ra **trong container**, và **không khớp kịch bản nào** mới được xem là hành vi lạ. Mỗi tên luật Falco chỉ được đề xuất **một lần** (xem lại hoặc đề xuất lại bằng cách xóa document tương ứng trong index `rule-proposals`).
- Luật AI đã duyệt có hậu tố `[AI-<id>]` trong tên (luật **thường**). Khi nó kích hoạt, `ai_processor` chỉ chấm mức **HIGH (50 điểm)**, **không** tự động dừng container.
- Nếu condition có **cả tên tiến trình lẫn tham số cụ thể** (vd. `proc.name = rm and proc.cmdline contains "/var/log/"`, không có `or` ngoài ngoặc) thì luật là luật **chặt**, tên có hậu tố `[AI-<id>-strict]`. Sau khi bạn duyệt, luật chặt chấm **80 điểm = CRITICAL**, nên `incident_responder` có thể tự dừng container. Tin Telegram ghi rõ luật thuộc loại nào. Luật chỉ lọc theo tên tiến trình (`rm`, `chmod`, ...) luôn là luật thường vì dễ dừng nhầm container hợp lệ.
- Chỉ người trong đúng `TELEGRAM_CHAT_ID` mới bấm duyệt được. Muốn giới hạn chặt hơn, đặt `TELEGRAM_APPROVER_IDS` trong `.env`.
- Luật chỉ có tác dụng với **lần xảy ra sau**, không cứu được lần tấn công đang diễn ra. Nếu hành vi không để lại alert Falco nào thì AI không có dữ liệu để sinh luật.
- `phi3:mini` là model nhỏ nên luật sinh ra đôi khi chưa tốt. Luôn đọc kỹ luật trước khi bấm Duyệt.
- Chạy `cd ai_rule_generator && python3 test_proposer.py` để kiểm thử logic mà không cần Kafka, Elasticsearch, Ollama hay Telegram.

## 🛠️ Sự cố thường gặp (Troubleshooting)

### 1. Filebeat/Metricbeat crash ngay khi khởi động

**Triệu chứng:** `docker compose logs filebeat` hoặc `metricbeat` báo lỗi dạng:
```
Exiting: error loading config file ("filebeat.yml") must be owned by the user identifier (uid=0) or root
```
Hậu quả: toàn bộ tín hiệu log và CPU không bao giờ tới được `ai_processor` (dù mã nguồn xử lý hoàn toàn đúng), khiến hệ thống chỉ phát hiện được sự cố qua Falco (syscall), không bao giờ lên tới ngưỡng CRITICAL cho các kịch bản cần tín hiệu log/CPU.

**Nguyên nhân:** hai service này bind-mount trực tiếp file cấu hình từ host (`./configs/filebeat.yml`, `./configs/metricbeat.yml`) vào container. Elastic Beats từ chối nạp file cấu hình không thuộc sở hữu `root` (uid=0) như một biện pháp bảo mật mặc định. Nếu file trên host thuộc sở hữu user thường (ví dụ user WSL của bạn), Beats sẽ crash ngay khi đọc config.

**Cách khắc phục — chạy trước khi `docker compose up` (và mỗi lần sửa lại 2 file này):**
```bash
sudo chown root:root configs/filebeat.yml configs/metricbeat.yml
sudo chmod go-w configs/filebeat.yml configs/metricbeat.yml
docker compose restart filebeat metricbeat
```

### 2. Dashboard Grafana / Data source biến mất, panel báo "No data"

**Triệu chứng:** truy cập lại link dashboard cũ báo "Dashboard not found", hoặc dashboard import lại được nhưng mọi panel đều hiện "No data" dù dữ liệu vẫn có trong Elasticsearch.

**Nguyên nhân:** Grafana lưu toàn bộ dashboard và cấu hình data source vào database nội bộ bên trong volume Docker `grafana_data`, **không có provisioning bằng file** trong project này. Nếu volume này bị xóa (chạy `docker compose down -v`, `docker volume prune`, hoặc chạy project trên một môi trường Docker khác — ví dụ đổi từ Docker Desktop Windows sang Docker Engine trong WSL), toàn bộ dashboard **và** data source đã cấu hình sẽ mất sạch, không thể khôi phục nếu chưa export ra file trước đó.

**Cách khắc phục khi đã mất:**
1. Tạo lại data source: **Connections > Data sources > Add new connection > Elasticsearch**, URL `http://elasticsearch:9200`, Index name `security-incidents`, bấm **Save & Test**.
2. Import lại dashboard từ file `Thongkemaucanhbaoanninh.json` (đã lưu sẵn trong repo): **Dashboards > New > Import > Upload dashboard JSON file**.
3. Nếu panel vẫn "No data" sau khi có data source, vào **Edit** từng panel, chọn lại đúng data source vừa tạo (dashboard cũ có thể còn trỏ tới UID data source cũ đã không còn tồn tại — Grafana sinh UID mới mỗi lần tạo lại data source).

**Cách phòng tránh về lâu dài:** thiết lập Grafana provisioning (đọc dashboard/data source từ file thay vì chỉ lưu trong volume) để cấu hình luôn được khôi phục tự động dù volume có bị xóa — xem hướng dẫn tại `docs/` (nếu đã thiết lập) hoặc liên hệ nhóm phát triển để bổ sung.

### 3. `generator.py` hoặc `rule_proposer` báo `404 Not Found` khi gọi Ollama

**Nguyên nhân:** model chưa được tải về. Model nằm trong volume `ollama_data`, nên `docker compose down -v` sẽ xóa luôn model.

**Cách khắc phục:** `docker exec -it siem-ollama ollama pull phi3:mini`. Từ giờ chỉ dùng `docker compose down` (không có `-v`) khi chỉ muốn dừng hệ thống.

### 4. `rule_proposer` báo `getUpdates lỗi HTTP 409`

**Nguyên nhân:** bot Telegram đang gắn webhook, hoặc có tiến trình khác cũng đang `getUpdates` bằng cùng token. Mỗi bot chỉ cho một nơi nhận nút bấm.

**Cách khắc phục:** tắt tiến trình còn lại, hoặc gỡ webhook: `curl "https://api.telegram.org/bot<TOKEN>/deleteWebhook"`.

## 📖 Tài liệu

- `docs/SETUP.md` — Hướng dẫn chi tiết setup
- `docs/ARCHITECTURE.md` — Kiến trúc hệ thống

## 🤝 Đóng góp

1. Fork repository
2. Tạo nhánh: `git checkout -b feature/your-feature`
3. Commit: `git commit -m "Add: your feature"`
4. Push: `git push origin feature/your-feature`
5. Tạo Pull Request

## 📧 Liên hệ

Nếu gặp vấn đề, tạo GitHub Issue hoặc liên hệ nhóm.

---
**Made with ❤️ by Security Team**

## 🧪 Quá trình thực hiện và kết quả: AI tự đề xuất luật cho hành vi chưa từng gặp (zero-day)

Phần này ghi lại quá trình xây dựng, thử nghiệm và kết quả đạt được của tính năng "AI tự sinh luật Falco, người duyệt qua Telegram". Số liệu và ảnh chụp lấy từ lần chạy thực tế ngày 16/10/2026 trên WSL2 (Kali), Falco chạy trên host bằng driver modern-bpf, mô hình `phi3:mini` chạy bằng Ollama.

### 1. Mục tiêu

Hệ thống ban đầu chỉ nhận diện được 4 kịch bản có sẵn (đào coin, reverse shell, brute-force SSH, rò rỉ dữ liệu). Mục tiêu của tính năng mới là xử lý trường hợp một hành vi đáng ngờ **chưa nằm trong kịch bản nào** xảy ra: AI soạn luật Falco, gửi cho người quản trị duyệt trên Telegram, và nếu được duyệt thì luật được nạp vào Falco để lần sau hệ thống nhận diện được.

### 2. Quy trình tổng thể

```
Falco báo hành vi lạ ──► ai_processor: không khớp kịch bản nào ──► topic unknown-threats
        ──► rule_proposer: nhờ AI (Ollama) soạn luật, kiểm tra bằng code
        ──► Telegram: gửi luật kèm nút Duyệt / Từ chối
        ──► Duyệt: ghi file falco_rules_approved/ai-<id>.yaml
        ──► falco_rule_sync.sh (trên host): kiểm tra bằng falco -V, chép vào /etc/falco/rules.d, nạp lại Falco
        ──► Lần sau hành vi lặp lại: Falco báo bằng luật mới ──► ai_processor chấm điểm ──► incident_responder xử lý ──► Telegram
```

Các nguyên tắc an toàn được giữ xuyên suốt:

1. **Luôn có người duyệt.** AI chỉ đề xuất, không tự áp dụng luật. Chỉ người đúng `TELEGRAM_CHAT_ID` (hoặc nằm trong `TELEGRAM_APPROVER_IDS`) mới bấm duyệt được.
2. **Luật AI mặc định chỉ cảnh báo.** Luật thường (tên có hậu tố `[AI-<id>]`) chỉ được chấm mức HIGH (50 điểm) nên không bao giờ tự dừng container.
3. **Chỉ luật "chặt" mới được tự dừng container.** Luật chặt (hậu tố `[AI-<id>-strict]`) bắt buộc có cả tên tiến trình lẫn tham số cụ thể, gắn với `spawned_process`, và không có `or` nối tên tiến trình với điều kiện khác. Luật chặt sau khi được duyệt chấm 80 điểm (CRITICAL).
4. **Có lớp bảo vệ phía host.** Script đồng bộ kiểm tra từng luật bằng `falco -V`, và gỡ luật vừa thêm nếu Falco không chạy được sau khi nạp.

### 3. Những vấn đề gặp phải và cách giải quyết

Bảng dưới đây tóm tắt các lỗi phát sinh trong quá trình thử nghiệm. Đây cũng là phần cho thấy vì sao luật do AI sinh ra không thể tin tưởng vô điều kiện.

| # | Hiện tượng quan sát được | Nguyên nhân | Cách khắc phục |
|---|---|---|---|
| 1 | Mô tả luật là tiếng Việt vô nghĩa | Prompt yêu cầu viết `desc` bằng tiếng Việt, model nhỏ viết kém | Mô tả do code tự điền, không dùng văn bản của model |
| 2 | Luật chứa nguyên `10.0.0.0/24` của lần tấn công | Prompt đưa IP và cmdline thật cho model nên nó chép lại | Che IP và container id (`<IP>`, `<ID>`) trước khi đưa vào prompt, và loại luật có IP cứng |
| 3 | Cú pháp `contains ("x")` sai | `contains` chỉ nhận một chuỗi, không nhận danh sách | Tự sửa trường hợp một phần tử, loại trường hợp nhiều phần tử |
| 4 | Luật `proc.name in (nmap, masscan, zmap)` cho hành vi xóa log bằng `rm` | Prompt có sẵn ví dụ nmap/masscan, model chép ví dụ thay vì dùng tiến trình thật | Bỏ ví dụ cụ thể khỏi prompt, thêm bước kiểm tra luật phải khớp tiến trình và cmdline của sự kiện đã quan sát |
| 5 | Luật gắn nhãn "chặt" nhưng điều kiện là `(proc.name in (rm) or proc.cmdline contains "/var/log/")` | `or` nối tên tiến trình với đường dẫn làm luật khớp mọi lệnh `rm` hoặc mọi lệnh có `/var/log/` | Chỉ cho phép `or` giữa các `proc.name`, loại luật có `or` trộn tên tiến trình với điều kiện khác |
| 6 | Falco bắt được luật mới nhưng không có sự cố nào | Container `connector` (cổng 2801, nhận cảnh báo từ Falco) đã thoát từ 4 ngày trước (`Exited (255)`), Falco báo `libcurl failed: Couldn't connect to server` | Bật lại `connector` và thêm `restart: unless-stopped` trong `docker-compose.yml` |

Ngoài ra, các lỗi môi trường đã gặp trước đó (Filebeat/Metricbeat thoát do file cấu hình sai chủ sở hữu, mất dữ liệu Grafana và model Ollama sau `docker compose down -v`) được ghi trong mục Troubleshooting.

### 4. Kết quả thử nghiệm

Tình huống thử: xóa log hệ thống trong container (`rm -rf /var/log/auth.log /var/log/syslog`), một hành vi chưa có kịch bản nào bao phủ.

| Bước | Kết quả quan sát được |
|---|---|
| Phát hiện hành vi lạ | `ai_processor` ghi `[UNKNOWN-THREAT]` và đẩy sang topic `unknown-threats` |
| AI đề xuất luật | Telegram nhận tin "AI đề xuất luật Falco mới" kèm nút Duyệt/Từ chối, luật được gắn nhãn Luật CHẶT |
| Duyệt luật | Telegram báo "Đã duyệt luật 9993456b93", tạo `falco_rules_approved/ai-9993456b93.yaml` |
| Nạp luật vào Falco | `falco_rule_sync.sh` chép luật vào `/etc/falco/rules.d`, nạp lại Falco, báo "Falco hoạt động bình thường, đã áp dụng 1 luật mới" |
| Falco bắt hành vi lặp lại | Falco báo luật `System Logs Deleted By RM Command [AI-9993456b93-strict]` cho container thật `victim_logwipe` |
| Chấm điểm | `ai_processor` ghi `[CRITICAL] scenario=ai_generated_strict score=80` và đẩy sự cố sang `threat-incidents` |
| Phản ứng | Container `victim_logwipe` chuyển sang `Exited (137)` |
| Thông báo | Telegram nhận "CẢNH BÁO AN NINH": CRITICAL, risk score 80, "Hành động: stop (success)" |

Như vậy chuỗi xử lý đầu cuối hoạt động: một hành vi lạ được phát hiện, AI đề xuất luật, người quản trị duyệt, luật được nạp vào Falco, và lần xảy ra sau hệ thống tự động ngăn chặn container và thông báo.

### 5. Hạn chế đã biết

- **Lần xảy ra đầu tiên không bị chặn.** Hệ thống chỉ phát hiện và đề xuất luật. Luật chỉ có tác dụng với những lần xảy ra sau khi được duyệt.
- **Chất lượng luật phụ thuộc mô hình.** `phi3:mini` là mô hình nhỏ, luật sinh ra có thể sai hoặc quá hẹp. Các lớp kiểm tra bằng code chỉ chặn được những dạng lỗi đã biết, vì vậy người duyệt vẫn cần đọc kỹ `condition` trước khi bấm Duyệt.
- **Luật có thể quá hẹp.** Luật trong lần thử đòi cả `/var/log/auth.log` lẫn `/var/log/syslog` trong cùng một lệnh nên không bắt được `rm -rf /var/log/*` hoặc chỉ xóa một file. Với luật tự động dừng container, hẹp là phía an toàn hơn rộng, nhưng sẽ bỏ sót một số cách tấn công.
- **Luật thường chỉ cảnh báo.** Luật AI không đủ điều kiện "chặt" chỉ tạo cảnh báo mức HIGH, không tự dừng container.
- **Phụ thuộc hạ tầng.** Chuỗi xử lý cần `connector` chạy liên tục để chuyển cảnh báo từ Falco sang Kafka. Đã thêm chính sách tự khởi động lại, nhưng nếu Docker không chạy thì hệ thống vẫn không nhận được cảnh báo.

### 6. Hướng phát triển

- Dùng mô hình lớn hơn (ví dụ qwen2.5:7b) hoặc đưa các luật đã được duyệt làm ví dụ mẫu trong prompt để tăng chất lượng.
- Thêm bước loại luật chép nguyên từng tên file trong cmdline để luật tổng quát hơn.
- Thử thêm các tình huống zero-day khác đã có sẵn trong `test_simulate_unknown.py`: `escape`, `setuid`, `cron`.
- Cho phép sửa luật trực tiếp trên Telegram trước khi duyệt.

### 7. Cách chạy lại thử nghiệm

```bash
# Khởi động hệ thống và bật script nạp luật trên máy host
docker compose up -d --build
sudo bash scripts/falco_rule_sync.sh            # giữ terminal này mở

# Tạo container nạn nhân và gửi tình huống zero-day giả lập
docker run -d --name victim_logwipe alpine sleep 3600
python3 test_simulate_unknown.py logwipe        # xem thêm: list | scan | escape | setuid | cron | all

# Sau khi duyệt luật trên Telegram và script đã nạp luật, thực hiện hành vi thật
docker exec victim_logwipe sh -c 'touch /var/log/auth.log /var/log/syslog; rm -rf /var/log/auth.log /var/log/syslog'

# Theo dõi kết quả
docker compose logs --tail=15 ai_processor
docker ps -a --filter name=victim_logwipe        # Exited là container đã bị dừng
```

Muốn chạy lại cùng một tình huống, xóa đề xuất cũ (`curl -X DELETE "localhost:9200/rule-proposals/_doc/<id>"`) và chạy `docker compose restart ai_processor`.
