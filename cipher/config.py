import yaml
from pathlib import Path


class CipherConfig:
    def __init__(self, path="cipher.yaml"):
        self.path = Path(path)

        if not self.path.exists():
            raise Exception("cipher.yaml not found")

        with open(self.path, "r") as f:
            self.data = yaml.safe_load(f)

    @property
    def trust_domain(self):
        return self.data["trust_domain"]

    @property
    def ca_path(self):
        return self.data["ca"]["path"]

    def service_cert(self, name):
        return self.data["services"][name]["cert"]

    def service_key(self, name):
        return self.data["services"][name]["key"]
