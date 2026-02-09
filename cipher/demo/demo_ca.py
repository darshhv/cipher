import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from ca.certificate_authority import CertificateAuthority

ca = CertificateAuthority()
ca.initialize()

ca.issue_service_certificate("payment-api")
ca.issue_service_certificate("user-service")
