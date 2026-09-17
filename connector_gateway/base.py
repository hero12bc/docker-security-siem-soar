"""
base.py — Interface chung cho mọi plugin gửi cảnh báo (Telegram, Zalo, PfSense...).
Mỗi plugin mới chỉ cần kế thừa AlertPlugin và cài đặt hàm send().
"""

from abc import ABC, abstractmethod


class AlertPlugin(ABC):
    @abstractmethod
    def send(self, incident: dict) -> None:
        """Nhận 1 dict sự cố (đã bao gồm action/action_status do SOAR gắn thêm)
        và gửi cảnh báo ra kênh tương ứng."""
        raise NotImplementedError
