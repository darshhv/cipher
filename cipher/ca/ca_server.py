from fastapi import FastAPI
from cipher.ca.certificate_authority import CertificateAuthority
from cipher.config import CipherConfig

app = FastAPI()

config = CipherConfig()
ca = CertificateAuthority(config.ca_path)


@app.get("/")
def health():
    return {"status": "Cipher CA running"}


@app.post("/issue/{service}")
def issue_cert(service: str):
    ca.issue_service_certificate(service)
    return {"issued_for": service}
