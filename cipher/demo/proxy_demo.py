from cipher.services.cert_validator import CertificateValidator
from cipher.policy.policy_engine import PolicyEngine
from cipher.proxy.sidecar_proxy import SidecarProxy
from cipher.telemetry.audit_logging import CipherTelemetry


def main():
    # Initialize core Cipher components
    validator = CertificateValidator("data/ca/root_ca.crt")
    telemetry = CipherTelemetry()
    policy_engine = PolicyEngine()

    # Configure policy rules
    source_identity = "spiffe://cipher.local/service/payment-api"
    destination_identity = "spiffe://cipher.local/service/user-service"

    policy_engine.allow(source_identity, destination_identity)

    # Create sidecar proxy for payment-api
    proxy = SidecarProxy(
        validator=validator,
        policy_engine=policy_engine,
        telemetry=telemetry,
        service_identity=source_identity,
    )

    print("\n--- Simulating Multiple Requests ---\n")

    for i in range(12):
        print(f"\nRequest #{i+1}")
        proxy.outbound_request(
            cert_path="data/payment-api/payment-api.crt",
            destination_identity=destination_identity,
        )


if __name__ == "__main__":
    main()
