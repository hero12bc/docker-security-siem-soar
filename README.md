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
