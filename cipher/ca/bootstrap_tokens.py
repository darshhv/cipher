from datetime import datetime, timedelta, timezone

import jwt


class BootstrapTokenManager:
    def __init__(self, secret, issuer="cipher-ca", audience="cipher-ca", ttl_seconds=300):
        self.secret = secret
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds

    def mint(self, service_name):
        now = datetime.now(timezone.utc)
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": service_name,
            "service_name": service_name,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self.ttl_seconds)).timestamp()),
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def validate(self, token, expected_service_name):
        payload = jwt.decode(
            token,
            self.secret,
            audience=self.audience,
            issuer=self.issuer,
            algorithms=["HS256"],
        )

        token_service_name = payload.get("service_name")
        if token_service_name != expected_service_name:
            raise ValueError("Token service mismatch")

        return payload
