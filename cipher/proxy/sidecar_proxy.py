from cipher.proxy.rotation_manager import CertificateRotationManager


class SidecarProxy:
    def __init__(self, validator, policy_engine, telemetry, service_identity, ca):
        self.validator = validator
        self.policy_engine = policy_engine
        self.telemetry = telemetry
        self.service_identity = service_identity
        self.ca = ca

    def start_rotation(self, cert_path, service_name):
        def renew():
            self.ca.issue_service_certificate(service_name)
            print("[Proxy] Certificate renewed")

        manager = CertificateRotationManager(cert_path, renew)
        manager.start()

    def outbound_request(self, cert_path, destination_identity):
        source_identity = self.validator.validate(cert_path)

        allowed = self.policy_engine.is_allowed(
            source_identity,
            destination_identity,
        )

        decision = "allow" if allowed else "deny"

        self.telemetry.log_event(
            source_identity,
            destination_identity,
            decision,
        )

        print(f"[Proxy] Decision logged: {decision}")
        return allowed
