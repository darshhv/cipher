import importlib
import sys
import types


def _fake_yaml_module():
    module = types.ModuleType("yaml")

    def safe_load(_stream):
        return {
            "paths": {"ca_dir": "./data/ca", "data_dir": "./data"},
            "ca": {"trust_domain": "cipher.local", "key_size": 2048, "cert_validity_hours": 24},
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


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload


def test_cli_enroll_integrates_token_and_issue_flow(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cipher-config.yaml").write_text("placeholder: true\n")
    monkeypatch.setitem(sys.modules, "yaml", _fake_yaml_module())

    import cipher.ca.ca_server as ca_server

    ca_server = importlib.reload(ca_server)

    def fake_post(url, json, headers=None):
        if url.endswith("/v1/enroll/token"):
            try:
                result = ca_server.issue_bootstrap_token(
                    ca_server.TokenRequest(service_name=json["service_name"]),
                    x_admin_token=(headers or {}).get("X-Admin-Token", ""),
                )
                return _Resp(200, result)
            except Exception as exc:
                return _Resp(getattr(exc, "status_code", 500), {"detail": str(exc)})

        if url.endswith("/v1/certificate"):
            try:
                result = ca_server.issue_cert(
                    ca_server.CertificateRequest(
                        service_name=json["service_name"],
                        bootstrap_token=json["bootstrap_token"],
                    )
                )
                return _Resp(200, result)
            except Exception as exc:
                return _Resp(getattr(exc, "status_code", 500), {"detail": str(exc)})

        return _Resp(404, {"detail": "unknown"})

    import cipher_cli

    monkeypatch.setenv("CIPHER_ADMIN_TOKEN", "test-admin-token")

    requests_module = types.ModuleType("requests")
    requests_module.post = fake_post
    monkeypatch.setitem(sys.modules, "requests", requests_module)

    cipher_cli.enroll_service("payment-api")
    out = capsys.readouterr().out

    assert "enrolled via CA API" in out
    assert (tmp_path / "data" / "payment-api" / "payment-api.crt").exists()
    assert (tmp_path / "data" / "payment-api" / "payment-api.key").exists()
