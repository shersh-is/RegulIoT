import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from services.cve_service import CVEService
from services.network_service import NetworkService
from services.ai_service import AIService
from services.notification_service import NotificationService
from config import BASE_DIR
from ui_app import MainWindow


def main():
    cve_service = CVEService(
        db_path=BASE_DIR / "database",
        meta_path=BASE_DIR / "cve_meta.json"
    )

    network_service = NetworkService()
    ai_service = AIService(
        cve_service=cve_service,
        model_path=BASE_DIR / "models_ai" / "catboost.cbm"
    )

    notification_service = NotificationService()

    app = QApplication(sys.argv)
    window = MainWindow(
        cve_service,
        network_service,
        ai_service,
        notification_service
    )
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
