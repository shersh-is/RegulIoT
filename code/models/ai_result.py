from dataclasses import dataclass
from models.vulnerability import Vulnerability

@dataclass
class AIResult:
    device_ip: str
    risk_score: float
    severity: str
    vulnerabilities: list[Vulnerability]
    recommendation: str
