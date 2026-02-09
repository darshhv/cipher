import yaml
from pathlib import Path


class CipherConfig:
    def __init__(self, path="cipher-config.yaml"):
        self.path = Path(path)

        if not self.path.exists():
            raise FileNotFoundError("cipher-config.yaml not found")

        with open(self.path) as f:
            self.data = yaml.safe_load(f)

    def get(self, section, key):
        return self.data[section][key]
