import ssl
import socket


def run_client():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(
        "data/payment-api/payment-api.crt",
        "data/payment-api/payment-api.key",
    )
    context.load_verify_locations("data/ca/root_ca.crt")

    sock = socket.create_connection(("127.0.0.1", 12000))
    ssock = context.wrap_socket(sock, server_hostname="user-service")

    print("Connected to secure service")

    print(ssock.recv(1024))
    ssock.close()


if __name__ == "__main__":
    run_client()
