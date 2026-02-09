from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime, timedelta
from pathlib import Path


class CertificateAuthority:
    def __init__(self, ca_dir="data/ca"):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self.key_path = self.ca_dir / "root_ca.key"
        self.cert_path = self.ca_dir / "root_ca.crt"

    def initialize(self):
        if self.key_path.exists() and self.cert_path.exists():
            print("Root CA already exists.")
            return

        print("Generating Root CA...")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cipher"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Cipher Root CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        with open(self.key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("Root CA created.")

    def issue_service_certificate(self, service_name):
        service_dir = Path(f"data/{service_name}")
        service_dir.mkdir(parents=True, exist_ok=True)

        service_key_path = service_dir / f"{service_name}.key"
        service_cert_path = service_dir / f"{service_name}.crt"

        with open(self.key_path, "rb") as f:
            ca_key = load_pem_private_key(f.read(), password=None)

        with open(self.cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        spiffe_id = f"spiffe://cipher.local/service/{service_name}"

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, service_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(service_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(hours=24))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(spiffe_id)]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with open(service_key_path, "wb") as f:
            f.write(service_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        with open(service_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"Certificate issued for {service_name}")
