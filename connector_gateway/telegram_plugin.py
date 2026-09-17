import os

import requests

from base import AlertPlugin


class TelegramPlugin(AlertPlugin):
    def __init__(self):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def _format_message(self, incident: dict) -> str:
        signals = ", ".join(incident.get("signals", []))
        return (
            "🚨 CẢNH BÁO AN NINH 🚨\n"
            f"Container: {incident.get('container_id')}\n"
            f"Mức độ: {incident.get('label')}\n"
            f"Risk score: {incident.get('risk_score')}\n"
            f"Tín hiệu: {signals}\n"
            f"Hành động: {incident.get('action', 'N/A')} "
            f"({incident.get('action_status', 'N/A')})\n"
            f"Thời gian: {incident.get('timestamp', '')}"
        )

    def send(self, incident: dict) -> None:
        if not self.token or not self.chat_id:
            print("[TelegramPlugin] Thiếu TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID, bỏ qua gửi.")
            return

        payload = {
            "chat_id": self.chat_id,
            "text": self._format_message(incident),
        }

        try:
            resp = requests.post(self.api_url, json=payload, timeout=5)
            resp.raise_for_status()
            print(
                f"[TelegramPlugin] Đã gửi cảnh báo Telegram cho "
                f"container={incident.get('container_id')}"
            )
        except Exception as e:
            print(f"[TelegramPlugin] Lỗi gửi Telegram: {e}")
