from cipher.policy.policy_engine import PolicyDecision, PolicyEngine, PolicyRule


def test_default_deny_when_no_rule_matches():
    engine = PolicyEngine()
    decision, _, matched_rule = engine.evaluate("a", "b", method="GET", path="/x")
    assert decision == PolicyDecision.DENY
    assert matched_rule == "default-deny"


def test_priority_based_rule_ordering():
    engine = PolicyEngine()
    engine.add_rule(
        PolicyRule(
            name="allow-low-priority",
            source_identity="*",
            destination_identity="*",
            action=PolicyDecision.ALLOW,
            priority=100,
        )
    )
    engine.add_rule(
        PolicyRule(
            name="deny-high-priority",
            source_identity="spiffe://cipher.local/service/a",
            destination_identity="spiffe://cipher.local/service/b",
            action=PolicyDecision.DENY,
            priority=10,
        )
    )

    decision, _, matched_rule = engine.evaluate(
        "spiffe://cipher.local/service/a",
        "spiffe://cipher.local/service/b",
        method="GET",
        path="/",
    )
    assert decision == PolicyDecision.DENY
    assert matched_rule == "deny-high-priority"


def test_method_and_path_matching():
    engine = PolicyEngine()
    engine.add_rule(
        PolicyRule(
            name="allow-read-api",
            source_identity="spiffe://cipher.local/service/a",
            destination_identity="spiffe://cipher.local/service/b",
            method="GET",
            path_pattern="/api/*",
            action=PolicyDecision.ALLOW,
            priority=5,
        )
    )

    allow_decision, _, _ = engine.evaluate(
        "spiffe://cipher.local/service/a",
        "spiffe://cipher.local/service/b",
        method="GET",
        path="/api/orders",
    )
    deny_decision, _, _ = engine.evaluate(
        "spiffe://cipher.local/service/a",
        "spiffe://cipher.local/service/b",
        method="POST",
        path="/api/orders",
    )

    assert allow_decision == PolicyDecision.ALLOW
    assert deny_decision == PolicyDecision.DENY


def test_throttle_rule_when_medium_risk():
    engine = PolicyEngine()
    engine.add_rule(
        PolicyRule(
            name="throttle-burst",
            source_identity="spiffe://cipher.local/service/a",
            destination_identity="spiffe://cipher.local/service/b",
            action=PolicyDecision.THROTTLE,
            priority=1,
        )
    )

    # warm up to medium risk band
    for _ in range(6):
        decision, risk, _ = engine.evaluate(
            "spiffe://cipher.local/service/a",
            "spiffe://cipher.local/service/b",
        )

    assert decision == PolicyDecision.THROTTLE
    assert risk >= 0.6


def test_high_risk_overrides_to_deny():
    engine = PolicyEngine()
    engine.add_rule(
        PolicyRule(
            name="allow-a-to-b",
            source_identity="spiffe://cipher.local/service/a",
            destination_identity="spiffe://cipher.local/service/b",
            action=PolicyDecision.ALLOW,
            priority=1,
        )
    )

    for _ in range(11):
        decision, risk, _ = engine.evaluate(
            "spiffe://cipher.local/service/a",
            "spiffe://cipher.local/service/b",
        )

    assert decision == PolicyDecision.DENY
    assert risk >= 0.8
