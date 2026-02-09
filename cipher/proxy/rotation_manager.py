import threading
import time
from datetime import datetime, timezone
from cryptography import x509


class CertificateRotationManager:
    def __init__(self, cert_path, renew_callback, interval=60):
        self.cert_path = cert_path
        self.renew_callback = renew_callback
        self.interval = interval
        self._running = False

    def start(self):
        self._running = True
        thread = threading.Thread(target=self._loop, daemon=True)
        thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            self._check_certificate()
            time.sleep(self.interval)

    def _check_certificate(self):
        try:
            with open(self.cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            # Use UTC everywhere
            now = datetime.now(timezone.utc)

            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            lifetime = not_after - not_before
            remaining = not_after - now

            print(f"[Rotation] Remaining lifetime: {remaining}")

            if remaining.total_seconds() < lifetime.total_seconds() / 2:
                print("[Rotation] Renewing certificate...")
                self.renew_callback()

        except Exception as e:
            print("[Rotation] Error:", e)
