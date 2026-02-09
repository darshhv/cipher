from policy.policy_engine import PolicyEngine

engine = PolicyEngine()

engine.allow(
    "spiffe://cipher.local/service/payment-api",
    "spiffe://cipher.local/service/user-service",
)

print(
    engine.is_allowed(
        "spiffe://cipher.local/service/payment-api",
        "spiffe://cipher.local/service/user-service",
    )
)

print(
    engine.is_allowed(
        "spiffe://cipher.local/service/user-service",
        "spiffe://cipher.local/service/payment-api",
    )
)
