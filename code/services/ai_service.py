from catboost import CatBoostClassifier
from models.ai_result import AIResult

class AIService:
    def __init__(self, cve_service, model_path):
        self.cve_service = cve_service
        self.model = CatBoostClassifier()
        self.model.load_model(model_path)

    def analyze(self, device):
        vulns = self.cve_service.search(
            device.vendor, device.product, device.firmware
        )

        features = [[len(vulns)]]
        risk = self.model.predict_proba(features)[0][1]

        severity = "CRITICAL" if risk > 0.8 else "HIGH" if risk > 0.5 else "LOW"

        return AIResult(
            device.ip,
            risk,
            severity,
            vulns,
            "Update firmware" if severity != "LOW" else "No action required"
        )
