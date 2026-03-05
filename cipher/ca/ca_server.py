import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from cipher.ca.bootstrap_tokens import BootstrapTokenManager
from cipher.ca.certificate_authority import CertificateAuthority
from cipher.config import CipherConfig
from cipher.telemetry.audit_logging import CipherTelemetry

app = FastAPI(title="Cipher CA Control Plane")

config = CipherConfig()
ca = CertificateAuthority(config)
ca.initialize()

telemetry = CipherTelemetry(db_path=config.get("telemetry", "db_path"))


class CertificateRequest(BaseModel):
    service_name: str
    bootstrap_token: str


class TokenRequest(BaseModel):
    service_name: str


def _cfg(section, key, default):
    try:
        return config.get(section, key)
    except Exception:
        return default


def _cfg_env(env_key, section, key, default):
    return os.environ.get(env_key, _cfg(section, key, default))


def _ensure_secure_runtime(admin_token, token_secret):
    env = os.environ.get("CIPHER_ENV", "dev").lower()
    insecure_admin = admin_token == "dev-admin-token-change-me"
    insecure_secret = token_secret == "dev-insecure-secret-change-me"

    if env not in {"dev", "development", "test"} and (insecure_admin or insecure_secret):
        raise RuntimeError(
            "Refusing to start CA server in non-dev environment with insecure default API secrets. "
            "Set CIPHER_ADMIN_TOKEN and CIPHER_TOKEN_SECRET (or api.admin_token/api.token_secret)."
        )


api_admin_token = _cfg_env("CIPHER_ADMIN_TOKEN", "api", "admin_token", "dev-admin-token-change-me")
api_token_secret = _cfg_env("CIPHER_TOKEN_SECRET", "api", "token_secret", "dev-insecure-secret-change-me")

_ensure_secure_runtime(api_admin_token, api_token_secret)

tokens = BootstrapTokenManager(
    secret=api_token_secret,
    issuer=_cfg_env("CIPHER_TOKEN_ISSUER", "api", "token_issuer", "cipher-ca"),
    audience=_cfg_env("CIPHER_TOKEN_AUDIENCE", "api", "token_audience", "cipher-ca"),
    ttl_seconds=int(_cfg_env("CIPHER_TOKEN_TTL_SECONDS", "api", "token_ttl_seconds", 300)),
)
tokens = BootstrapTokenManager(
    secret=_cfg("api", "token_secret", "dev-insecure-secret-change-me"),
    issuer=_cfg("api", "token_issuer", "cipher-ca"),
    audience=_cfg("api", "token_audience", "cipher-ca"),
    ttl_seconds=_cfg("api", "token_ttl_seconds", 300),
)

admin_token = _cfg("api", "admin_token", "dev-admin-token-change-me")


@app.get("/")
def root():
    return {"status": "Cipher CA running"}


@app.get("/v1/ca/cert")
def get_ca_cert():
    with open(ca.cert_path, "r") as f:
        return {"root_ca": f.read()}


@app.post("/v1/enroll/token")
def issue_bootstrap_token(req: TokenRequest, x_admin_token: str = Header(default="")):
    if x_admin_token != api_admin_token:
        telemetry.log_security_event(
            event_type="enrollment.token_mint",
            outcome="failure",
            reason="unauthorized_admin_header",
            details={"service_name": req.service_name},
        )
        raise HTTPException(status_code=401, detail="unauthorized")

    token = tokens.mint(req.service_name)
    telemetry.log_security_event(
        event_type="enrollment.token_mint",
        outcome="success",
        reason="issued",
        details={"service_name": req.service_name},
    )
        raise HTTPException(status_code=401, detail="unauthorized")

    token = tokens.mint(req.service_name)
    return {"service_name": req.service_name, "bootstrap_token": token}


@app.post("/v1/certificate")
def issue_cert(req: CertificateRequest):
    try:
        tokens.validate(req.bootstrap_token, req.service_name)
    except Exception as exc:
        telemetry.log_security_event(
            event_type="enrollment.token_validate",
            outcome="failure",
            reason=str(exc),
            details={"service_name": req.service_name},
        )
        raise HTTPException(status_code=401, detail=f"invalid bootstrap token: {exc}")

    ca.issue_service_certificate(req.service_name)
    telemetry.log_security_event(
        event_type="certificate.issue",
        outcome="success",
        reason="issued",
        destination_identity=req.service_name,
        details={"service_name": req.service_name},
    )
    return {"issued": req.service_name}
