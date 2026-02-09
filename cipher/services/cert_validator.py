from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone


class CertificateValidator:
    def __init__(self, root_ca_path):
        with open(root_ca_path, "rb") as f:
            self.root_cert = x509.load_pem_x509_certificate(f.read())

    def validate(self, cert_path):
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        # Time validation (timezone-aware)
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise Exception("Certificate expired or invalid")

        # Signature verification (chain validation against root CA)
        self.root_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        # Extract SPIFFE identity
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        identity = list(san.value)[0].value
        return identity
