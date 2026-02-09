import sys


def init_cipher():
    from cipher.ca.certificate_authority import CertificateAuthority
    from cipher.config import CipherConfig

    config = CipherConfig()
    ca = CertificateAuthority(config.ca_path)
    ca.initialize()

    print("Cipher initialized successfully.")


def enroll_service(service_name):
    from cipher.ca.certificate_authority import CertificateAuthority
    from cipher.config import CipherConfig

    config = CipherConfig()
    ca = CertificateAuthority(config.ca_path)
    ca.issue_service_certificate(service_name)

    print(f"Service '{service_name}' enrolled.")


def run_demo():
    from cipher.demo.proxy_demo import main
    main()


def run_ca_server():
    import uvicorn
    from cipher.ca.ca_server import app

    uvicorn.run(app, host="127.0.0.1", port=9000)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  cipher-cli init")
        print("  cipher-cli enroll <service>")
        print("  cipher-cli demo")
        print("  cipher-cli ca-server")
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


if __name__ == "__main__":
    main()
