import os
import sys


def init_cipher():
    from cipher.ca.certificate_authority import CertificateAuthority
    from cipher.config import CipherConfig

    config = CipherConfig()
    ca = CertificateAuthority(config)
    ca.initialize()

    print("Cipher initialized successfully.")


def enroll_service(service_name):
    import requests

    admin_token = os.environ.get("CIPHER_ADMIN_TOKEN", "dev-admin-token-change-me")
    token_url = "http://127.0.0.1:9000/v1/enroll/token"
    cert_url = "http://127.0.0.1:9000/v1/certificate"

    try:
        token_resp = requests.post(
            token_url,
            json={"service_name": service_name},
            headers={"X-Admin-Token": admin_token},
        )

        if token_resp.status_code != 200:
            print("Could not mint bootstrap token:", token_resp.text)
            return

        bootstrap_token = token_resp.json()["bootstrap_token"]

        cert_resp = requests.post(
            cert_url,
            json={
                "service_name": service_name,
                "bootstrap_token": bootstrap_token,
            },
        )

        if cert_resp.status_code == 200:
            print(f"Service '{service_name}' enrolled via CA API.")
        else:
            print("Enrollment failed:", cert_resp.text)

    except Exception as e:
        print("Could not reach CA server.")
        print("Start it with: cipher-cli ca-server")
        print("Error:", e)


def run_demo():
    from cipher.demo.proxy_demo import main

    main()


def run_ca_server():
    import uvicorn
    from cipher.ca.ca_server import app

    uvicorn.run(app, host="127.0.0.1", port=9000)


def print_usage():
    print("\nCipher CLI")
    print("-----------")
    print("cipher-cli init")
    print("cipher-cli enroll <service>")
    print("cipher-cli demo")
    print("cipher-cli ca-server")
    print("env: CIPHER_ADMIN_TOKEN=<admin token>\n")


def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    cmd = sys.argv[1]

    if cmd == "init":
        init_cipher()

    elif cmd == "enroll":
        if len(sys.argv) < 3:
            print("Provide service name")
            return
        enroll_service(sys.argv[2])

    elif cmd == "demo":
        run_demo()

    elif cmd == "ca-server":
        run_ca_server()

    else:
        print("Unknown command")
        print_usage()


if __name__ == "__main__":
    main()
