from abc import ABC, abstractmethod
from pathlib import Path


class KeyStore(ABC):
    @abstractmethod
    def write_private_key(self, path, key_pem_bytes):
        raise NotImplementedError

    @abstractmethod
    def read_private_key(self, path):
        raise NotImplementedError


class CertificateStore(ABC):
    @abstractmethod
    def write_certificate(self, path, cert_pem_bytes):
        raise NotImplementedError

    @abstractmethod
    def read_certificate(self, path):
        raise NotImplementedError


class FileKeyStore(KeyStore):
    def write_private_key(self, path, key_pem_bytes):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key_pem_bytes)

    def read_private_key(self, path):
        return Path(path).read_bytes()


class FileCertificateStore(CertificateStore):
    def write_certificate(self, path, cert_pem_bytes):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(cert_pem_bytes)

    def read_certificate(self, path):
        return Path(path).read_bytes()


class KMSKeyStore(KeyStore):
    """KMS-backed key-store placeholder for future provider integration."""

    def __init__(self, provider_name="kms"):
        self.provider_name = provider_name

    def write_private_key(self, path, key_pem_bytes):
        raise NotImplementedError(
            f"{self.provider_name} key-store provider is not implemented yet"
        )

    def read_private_key(self, path):
        raise NotImplementedError(
            f"{self.provider_name} key-store provider is not implemented yet"
        )
