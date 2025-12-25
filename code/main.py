import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from services.cve_service import CVEService
from services.network_service import NetworkService
from services.ai_service import AIService
from services.notification_service import NotificationService
from services.application_service import ApplicationService
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

    application_service = ApplicationService(
        network_service=network_service,
        cve_service=cve_service,
        ai_service=ai_service,
        notification_service=notification_service
    )

    app = QApplication(sys.argv)
    window =window = MainWindow(application_service)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

