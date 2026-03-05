from pathlib import Path

import pytest

from cipher.ca.stores import FileCertificateStore, FileKeyStore, KMSKeyStore


def test_file_stores_read_write(tmp_path):
    key_store = FileKeyStore()
    cert_store = FileCertificateStore()

    key_path = tmp_path / "keys" / "a.key"
    cert_path = tmp_path / "certs" / "a.crt"

    key_store.write_private_key(key_path, b"KEY")
    cert_store.write_certificate(cert_path, b"CERT")

    assert key_store.read_private_key(key_path) == b"KEY"
    assert cert_store.read_certificate(cert_path) == b"CERT"


def test_kms_store_is_placeholder():
    kms = KMSKeyStore(provider_name="aws-kms")

    with pytest.raises(NotImplementedError):
        kms.write_private_key(Path("x"), b"x")

    with pytest.raises(NotImplementedError):
        kms.read_private_key(Path("x"))
