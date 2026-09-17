# Kiến trúc Hệ thống SIEM/SOAR

## Sơ đồ Luồng Dữ liệu

Docker Containers (Metricbeat, Filebeat, Falco) ↓ Kafka (Message Bus) ↓ Elasticsearch (Storage) ↓ Grafana (Visualization) ↓ AI Processor (Correlation) ↓ SOAR (Incident Response) ↓ Connector Gateway (Telegram Alert)


## Chi tiết Components

### 1. Metricbeat
- Thu thập CPU, RAM, metrics container
- Đẩy vào Kafka topic: `docker-metrics`

### 2. Filebeat
- Thu thập log container
- Đẩy vào Kafka topic: `docker-logs`

### 3. Falco
- Giám sát syscall (eBPF)
- Đẩy vào Kafka topic: `docker-syscalls`

### 4. Kafka
- Message broker trung tâm
- Topics: docker-metrics, docker-logs, docker-syscalls, threat-incidents

### 5. Elasticsearch
- Lưu trữ & index dữ liệu

### 6. Grafana
- Visualize dữ liệu từ Elasticsearch

### 7. AI Processor
- Consumer 3 Kafka topics
- Correlation & Risk Scoring
- Producer topic: threat-incidents

### 8. SOAR (Incident Responder)
- Consumer topic: threat-incidents
- Gọi Docker API dừng container

### 9. Connector Gateway
- Gửi cảnh báo qua Telegram

---
