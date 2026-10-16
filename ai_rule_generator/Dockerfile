FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY generator.py proposer.py seed_rules.yaml ./
CMD ["python", "-u", "proposer.py"]
