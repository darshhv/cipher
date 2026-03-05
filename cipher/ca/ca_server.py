from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from cipher.ca.bootstrap_tokens import BootstrapTokenManager
from cipher.ca.certificate_authority import CertificateAuthority
from cipher.config import CipherConfig

app = FastAPI(title="Cipher CA Control Plane")

config = CipherConfig()
ca = CertificateAuthority(config)
ca.initialize()


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
    if x_admin_token != admin_token:
        raise HTTPException(status_code=401, detail="unauthorized")

    token = tokens.mint(req.service_name)
    return {"service_name": req.service_name, "bootstrap_token": token}


@app.post("/v1/certificate")
def issue_cert(req: CertificateRequest):
    try:
        tokens.validate(req.bootstrap_token, req.service_name)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"invalid bootstrap token: {exc}")

    ca.issue_service_certificate(req.service_name)
    return {"issued": req.service_name}
