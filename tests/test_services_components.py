import sys
import types
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _fake_yaml_module():
    module = types.ModuleType("yaml")

    def safe_load(_stream):
        return {
            "paths": {"ca_dir": "./data/ca", "data_dir": "./data"},
            "ca": {
                "trust_domain": "cipher.local",
                "key_size": 2048,
                "cert_validity_hours": 24,
            },
            "policy": {"deny_threshold": 0.8, "throttle_threshold": 0.6},
            "telemetry": {"db_path": "./data/cipher_audit.db"},
            "api": {
                "admin_token": "test-admin-token",
                "token_secret": "this-is-a-long-enough-test-secret-32chars",
                "token_issuer": "cipher-ca",
                "token_audience": "cipher-ca",
                "token_ttl_seconds": 300,
            },
        }

    module.safe_load = safe_load
    return module


def test_certificate_validator_extracts_spiffe_identity(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cipher-config.yaml").write_text("placeholder: true\n")
    monkeypatch.setitem(sys.modules, "yaml", _fake_yaml_module())

    from cipher.ca.certificate_authority import CertificateAuthority
    from cipher.config import CipherConfig
    from cipher.services.cert_validator import CertificateValidator

    ca = CertificateAuthority(CipherConfig())
    ca.initialize()
    ca.issue_service_certificate("payment-api")

    validator = CertificateValidator("data/ca/root_ca.crt")
    identity = validator.validate("data/payment-api/payment-api.crt")

    assert identity == "spiffe://cipher.local/service/payment-api"


def test_rotation_manager_renews_when_cert_below_half_life(tmp_path):
    from cipher.proxy.rotation_manager import CertificateRotationManager

    cert_path = tmp_path / "short.crt"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rotation-test")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(hours=9))
        .not_valid_after(datetime.utcnow() + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    called = {"value": False}

    def renew_callback():
        called["value"] = True

    manager = CertificateRotationManager(str(cert_path), renew_callback, interval=1)
    manager._check_certificate()

    assert called["value"] is True
