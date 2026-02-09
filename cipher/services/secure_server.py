import ssl
import socket

from cipher.policy.policy_engine import PolicyEngine
from cipher.telemetry.audit_logging import CipherTelemetry


policy = PolicyEngine()
telemetry = CipherTelemetry()

policy.allow(
    "spiffe://cipher.local/service/payment-api",
    "spiffe://cipher.local/service/user-service",
)


def extract_identity(cert_dict):
    for item in cert_dict.get("subjectAltName", []):
        if item[0] == "URI":
            return item[1]
    return "unknown"


def run_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        "data/user-service/user-service.crt",
        "data/user-service/user-service.key",
    )
    context.load_verify_locations("data/ca/root_ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    bindsocket.bind(("127.0.0.1", 12000))
    bindsocket.listen(5)

    print("Cipher secure service running on port 12000")

    while True:
        newsocket, _ = bindsocket.accept()

        try:
            conn = context.wrap_socket(newsocket, server_side=True)

            cert = conn.getpeercert()
            source_identity = extract_identity(cert)
            destination_identity = "spiffe://cipher.local/service/user-service"

            allowed = policy.is_allowed(source_identity, destination_identity)

            decision = "allow" if allowed else "deny"
            telemetry.log_event(source_identity, destination_identity, decision)

            print(f"[Cipher Gateway] {source_identity} → {decision}")

            if allowed:
                conn.send(b"Request accepted")
            else:
                conn.send(b"Access denied")

            conn.close()

        except ssl.SSLError as e:
            print("TLS error:", e)


if __name__ == "__main__":
    run_server()
