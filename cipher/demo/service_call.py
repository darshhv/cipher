from services.cert_validator import CertificateValidator
from policy.policy_engine import PolicyEngine

validator = CertificateValidator("data/ca/root_ca.crt")

policy = PolicyEngine()
policy.allow(
    "spiffe://cipher.local/service/payment-api",
    "spiffe://cipher.local/service/user-service",
)

source_identity = validator.validate(
    "data/payment-api/payment-api.crt"
)

destination_identity = "spiffe://cipher.local/service/user-service"

print("Source:", source_identity)
print("Destination:", destination_identity)

if policy.is_allowed(source_identity, destination_identity):
    print("Request allowed")
else:
    print("Request denied")
