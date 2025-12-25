from catboost import CatBoostClassifier
from models.ai_result import AIResult

class AIService:
    def __init__(self, cve_service, model_path):
        self.cve_service = cve_service
        self.model = CatBoostClassifier()
        self.model.load_model(model_path)

    def analyze(self, device):
        vulns = self.cve_service.search(
            device.vendor,
            device.product,
            device.firmware
        )

        vendor_len = len(device.vendor)
        product_len = len(device.product)

        cvss_scores = [
            getattr(v, "severity_score", 0)
            for v in vulns
            if hasattr(v, "severity_score")
        ]
        max_cvss = max(cvss_scores) if cvss_scores else 0.0
        cvss_norm = max_cvss / 10.0

        features = [[
            vendor_len,
            product_len,
            cvss_norm
        ]]

        risk_prob = self.model.predict_proba(features)[0][1]

        if risk_prob > 0.8:
            severity = "CRITICAL"
            recommendation = "Deactivate device or isolate network segment"
        elif risk_prob > 0.5:
            severity = "HIGH"
            recommendation = "Update firmware immediately"
        elif risk_prob > 0.2:
            severity = "MEDIUM"
            recommendation = "Monitor device and schedule update"
        else:
            severity = "LOW"
            recommendation = "No action required"

        return AIResult(
            device_ip=device.ip,
            risk_score=risk_prob,
            severity=severity,
            vulnerabilities=vulns,
            recommendation=recommendation
        )
