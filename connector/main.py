import json
from fastapi import FastAPI, Request
from kafka import KafkaProducer

app = FastAPI()

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

@app.post("/")
async def receive_falco_alert(request: Request):
    payload = await request.json()
    producer.send('docker-syscalls', payload)
    producer.flush()
    return {"status": "success", "message": "Syscall alert routed to Kafka"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=2801)
