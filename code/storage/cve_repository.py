import json
from models.vulnerability import Vulnerability

class CVERepository:
    def __init__(self, db_path):
        self.db_path = db_path

    def load_all(self):
        vulns = []
        for file in self.db_path.iterdir():
            data = json.loads(file.read_text(encoding="utf-8"))
            cna = data["containers"]["cna"]

            vulns.append(Vulnerability(
                cve_id=data["cveMetadata"]["cveId"],
                description=cna["descriptions"][0]["value"],
                severity=cna.get("metrics", [{}])[0]
                         .get("cvssV3_1", {})
                         .get("baseSeverity"),
                references=[r["url"] for r in cna.get("references", [])]
            ))
        return vulns
