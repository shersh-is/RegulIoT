class ApplicationService:
    def __init__(
        self,
        network_service,
        cve_service,
        ai_service,
        notification_service
    ):
        self.network_service = network_service
        self.cve_service = cve_service
        self.ai_service = ai_service
        self.notification_service = notification_service

    def run_full_scan(self):
        """
        Полный сценарий:
        1. Сканирование сети
        2. Анализ каждого устройства
        3. Уведомление пользователя при высоком риске
        """

        # Check CVE updates
        if self.cve_service.check_updates():
            self.cve_service.update()

        # Scan network
        devices = self.network_service.scan()

        results = []

        # Device analysis
        for device in devices:
            ai_result = self.ai_service.analyze(device)
            results.append(ai_result)

            # Notification if real vulnerability
            if ai_result.severity in ("HIGH", "CRITICAL"):
                self.notification_service.send(ai_result)

        return results
