from cryptography import x509

with open("data/payment-api/payment-api.crt", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

san = cert.extensions.get_extension_for_class(
    x509.SubjectAlternativeName
)

print("SPIFFE Identity:")
for uri in san.value:
    print(uri.value)
