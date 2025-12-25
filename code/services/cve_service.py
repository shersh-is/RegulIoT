import json, shutil, requests
from datetime import datetime
from storage.cve_repository import CVERepository

class CVEService:
    ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"

    def __init__(self, db_path, meta_path):
        self.db_path = db_path
        self.meta_path = meta_path
        self.repo = CVERepository(db_path)
        self.db_path.mkdir(exist_ok=True)

    def check_updates(self):
        r = requests.get("https://api.github.com/repos/CVEProject/cvelistV5/commits/main")
        remote = r.json()["commit"]["committer"]["date"]
        local = self._load_meta().get("updated")
        return remote != local

    def update(self):
        zip_path = self.db_path.parent / "cve.zip"
        zip_path.write_bytes(requests.get(self.ZIP_URL).content)
        shutil.unpack_archive(zip_path, self.db_path.parent)
        zip_path.unlink()

        src = self.db_path.parent / "cvelistV5-main" / "cves"
        shutil.rmtree(self.db_path)
        self.db_path.mkdir()

        year = datetime.now().year
        for y in [str(year), str(year - 1)]:
            for sub in (src / y).iterdir():
                for file in sub.iterdir():
                    shutil.move(file, self.db_path)

        shutil.rmtree(self.db_path.parent / "cvelistV5-main")
        self._save_meta()

    def search(self, vendor, product, version=None):
        return [
            v for v in self.repo.load_all()
            if vendor.lower() in v.description.lower()
            or product.lower() in v.description.lower()
        ]

    def _save_meta(self):
        self.meta_path.write_text(json.dumps({
            "updated": datetime.utcnow().isoformat()
        }))

    def _load_meta(self):
        if self.meta_path.exists():
            return json.loads(self.meta_path.read_text())
        return {}

