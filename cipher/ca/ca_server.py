from fastapi import FastAPI
from pydantic import BaseModel

from cipher.ca.certificate_authority import CertificateAuthority
from cipher.config import CipherConfig

app = FastAPI(title="Cipher CA Control Plane")

config = CipherConfig()
ca = CertificateAuthority(config)


class CertificateRequest(BaseModel):
    service_name: str


@app.get("/")
def root():
    return {"status": "Cipher CA running"}


@app.get("/v1/ca/cert")
def get_ca_cert():
    with open(ca.cert_path, "r") as f:
        return {"root_ca": f.read()}


@app.post("/v1/certificate")
def issue_cert(req: CertificateRequest):
    ca.issue_service_certificate(req.service_name)
    return {"issued": req.service_name}
