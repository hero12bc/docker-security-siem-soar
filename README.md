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

## 🚀 Cài đặt Nhanh

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/docker-security-siem-soar.git
cd docker-security-siem-soar

# 2. Cấu hình
cp .env.example .env
nano .env  # Điền Telegram Bot Token

# 3. Chạy
docker compose up -d --build

# 4. Truy cập
# Grafana: http://localhost:3000
# Elasticsearch: http://localhost:9200
```

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
