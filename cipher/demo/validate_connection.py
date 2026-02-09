from services.cert_validator import CertificateValidator

validator = CertificateValidator("data/ca/root_ca.crt")

identity = validator.validate("data/payment-api/payment-api.crt")

print("Verified identity:", identity)
