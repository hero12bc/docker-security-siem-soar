# Hướng dẫn Setup chi tiết

## Bước 1: Clone Repository
\`\`\`bash
git clone https://github.com/YOUR_USERNAME/docker-security-siem-soar.git
cd docker-security-siem-soar
\`\`\`

## Bước 2: Cấu hình .env
\`\`\`bash
cp .env.example .env
nano .env  # Điền Telegram Token & Chat ID
\`\`\`

## Bước 3: Khởi chạy
\`\`\`bash
docker compose up -d --build
docker compose ps
\`\`\`

## Bước 4: Truy cập
- Grafana: http://localhost:3000
- Elasticsearch: http://localhost:9200

## Bước 5: Import Dashboard
1. Vào Grafana
2. Dashboards → Import
3. Upload file: dashboards/thong-ke-canh-bao.json

---
Nếu gặp lỗi, xem phần Troubleshooting trong README.md
