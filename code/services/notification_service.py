from PyQt6.QtWidgets import QMessageBox

class NotificationService:
    def send(self, ai_result):
        QMessageBox.warning(
            None,
            "Уязвимость обнаружена",
            f"{ai_result.device_ip}\n"
            f"Risk: {ai_result.severity}\n"
            f"{ai_result.recommendation}"
        )
      
