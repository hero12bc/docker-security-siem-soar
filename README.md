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

Tại menu bên trái, chọn Dashboards -> Bấm nút New (góc trên bên phải) -> Chọn Import.

Bấm Upload dashboard JSON file.

Chọn file dashboard.json trong thư mục configs/grafana/ (hoặc docs/) của project.

Bấm Import để hoàn tất.

3. Chạy Kịch Bản Kiểm Thử (Attack Simulation)

# 1. Tạo container nạn nhân
1.Xóa container test cũ:Ngay lập tức.Xóa container victim hiện tại:Bashdocker rm -f victim_container 2>/dev/null; echo ok
Cách xác minh: Terminal xuất ra ok.
# 2. Kích hoạt kịch bản đào coin
2.Tạo container nạn nhân mới (giả lập đào coin):Ngay lập tức.Chạy lệnh tạo container victim thực hiện tải CPU và tạo log mining:Bashset +H; docker run -d --name victim_container alpine sh -c "printf '#!/bin/sh\ncat /etc/shadow > /dev/null\nsleep 3600\n' > /tmp/xmrig; chmod +x /tmp/xmrig; echo 'connecting to pool stratum+tcp://xmrig.pool.minexmr.com:4444'; yes > /dev/null & /tmp/xmrig"
Cách xác minh: Terminal trả về ID đầy đủ của container mới vừa khởi chạy.3.Quan sát log của ai_processor:Theo dõi 90 giây.Xem log trực tiếp để kiểm tra chỉ số age_cpu:Bashdocker compose logs -f --tail=0 ai_processor
Cách xác minh: Quan sát các dòng [DEBUG-AGE]. Chỉ số age_cpu bắt đầu cập nhật về dạng 0.0s, 10.0s... (thay vì cố định -1.0s) và cảnh báo đẩy lên mức CRITICAL (score = 100).

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
