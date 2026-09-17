"""
main.py — Connector Gateway (Giai đoạn 5)
Nhận sự cố (đã qua SOAR xử lý) qua POST /alert, forward tới mọi plugin đã đăng ký
(hiện tại: Telegram). Thêm plugin mới (Zalo, PfSense...) chỉ cần viết file kế
thừa AlertPlugin trong base.py rồi thêm vào danh sách `plugins` bên dưới.
"""

import uvicorn
from fastapi import FastAPI, Request

from telegram_plugin import TelegramPlugin

app = FastAPI()

plugins = [
    TelegramPlugin(),
    # PfSensePlugin(),  # bỏ comment khi có PfSense để test (Giai đoạn 5 - tùy chọn)
]


@app.post("/alert")
async def receive_alert(request: Request):
    incident = await request.json()

    results = []
    for plugin in plugins:
        try:
            plugin.send(incident)
            results.append({"plugin": type(plugin).__name__, "status": "sent"})
        except Exception as e:
            results.append({"plugin": type(plugin).__name__, "status": f"error: {e}"})

    return {"status": "forwarded", "results": results}


@app.get("/health")
async def health():
    return {"status": "ok", "plugins": [type(p).__name__ for p in plugins]}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=2802)
