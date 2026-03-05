import importlib
import sys
import types
from pathlib import Path

import pytest
from fastapi import HTTPException


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


def _load_ca_server(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cipher-config.yaml").write_text("placeholder: true\n")
    monkeypatch.setitem(sys.modules, "yaml", _fake_yaml_module())

    import cipher.ca.ca_server as ca_server

    return importlib.reload(ca_server)


def test_enroll_token_requires_admin_header(monkeypatch, tmp_path):
    ca_server = _load_ca_server(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc:
        ca_server.issue_bootstrap_token(
            ca_server.TokenRequest(service_name="payment-api"),
            x_admin_token="",
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "unauthorized"


def test_enroll_token_with_admin_header_returns_token(monkeypatch, tmp_path):
    ca_server = _load_ca_server(monkeypatch, tmp_path)

    response = ca_server.issue_bootstrap_token(
        ca_server.TokenRequest(service_name="payment-api"),
        x_admin_token="test-admin-token",
    )

    assert response["service_name"] == "payment-api"
    assert response["bootstrap_token"]


def test_certificate_issuance_rejects_invalid_token(monkeypatch, tmp_path):
    ca_server = _load_ca_server(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc:
        ca_server.issue_cert(
            ca_server.CertificateRequest(
                service_name="payment-api",
                bootstrap_token="not-a-valid-token",
            )
        )

    assert exc.value.status_code == 401
    assert "invalid bootstrap token" in exc.value.detail


def test_certificate_issuance_rejects_service_mismatch(monkeypatch, tmp_path):
    ca_server = _load_ca_server(monkeypatch, tmp_path)

    token_response = ca_server.issue_bootstrap_token(
        ca_server.TokenRequest(service_name="payment-api"),
        x_admin_token="test-admin-token",
    )

    with pytest.raises(HTTPException) as exc:
        ca_server.issue_cert(
            ca_server.CertificateRequest(
                service_name="user-service",
                bootstrap_token=token_response["bootstrap_token"],
            )
        )

    assert exc.value.status_code == 401
    assert "invalid bootstrap token" in exc.value.detail


def test_certificate_issuance_succeeds_with_valid_token(monkeypatch, tmp_path):
    ca_server = _load_ca_server(monkeypatch, tmp_path)

    token_response = ca_server.issue_bootstrap_token(
        ca_server.TokenRequest(service_name="payment-api"),
        x_admin_token="test-admin-token",
    )

    response = ca_server.issue_cert(
        ca_server.CertificateRequest(
            service_name="payment-api",
            bootstrap_token=token_response["bootstrap_token"],
        )
    )

    assert response == {"issued": "payment-api"}
    assert (tmp_path / "data" / "payment-api" / "payment-api.crt").exists()
    assert (tmp_path / "data" / "payment-api" / "payment-api.key").exists()
