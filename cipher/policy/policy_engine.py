from dataclasses import dataclass
from enum import Enum
import fnmatch


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    THROTTLE = "throttle"


@dataclass
class PolicyRule:
    name: str
    source_identity: str = "*"
    destination_identity: str = "*"
    method: str = "*"
    path_pattern: str = "*"
    action: PolicyDecision = PolicyDecision.ALLOW
    priority: int = 100

    def matches(self, source, destination, method="*", path="/"):
        return (
            fnmatch.fnmatch(source, self.source_identity)
            and fnmatch.fnmatch(destination, self.destination_identity)
            and fnmatch.fnmatch(method.upper(), self.method.upper())
            and fnmatch.fnmatch(path, self.path_pattern)
        )


class PolicyEngine:
    def __init__(self):
        self.rules = []
        self.request_counts = {}

    def add_rule(self, rule: PolicyRule):
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def allow(self, source, destination):
        # Backward compatibility helper
        self.add_rule(
            PolicyRule(
                name=f"allow-{source}-to-{destination}",
                source_identity=source,
                destination_identity=destination,
                action=PolicyDecision.ALLOW,
                priority=100,
            )
        )

    def risk_score(self, source, destination):
        key = (source, destination)
        count = self.request_counts.get(key, 0) + 1
        self.request_counts[key] = count

        if count > 10:
            return 0.9
        if count > 5:
            return 0.6
        return 0.1

    def evaluate(self, source, destination, method="GET", path="/"):
        for rule in self.rules:
            if rule.matches(source, destination, method=method, path=path):
                risk = self.risk_score(source, destination)

                # deterministic deny-by-default + high-risk deny override
                if risk >= 0.8:
                    return PolicyDecision.DENY, risk, rule.name

                if rule.action == PolicyDecision.THROTTLE and risk >= 0.6:
                    return PolicyDecision.THROTTLE, risk, rule.name

                return rule.action, risk, rule.name

        risk = self.risk_score(source, destination)
        return PolicyDecision.DENY, risk, "default-deny"

    def is_allowed(self, source, destination, method="GET", path="/"):
        decision, risk, matched_rule = self.evaluate(
            source,
            destination,
            method=method,
            path=path,
        )
        print(f"[Policy] Decision={decision.value} risk={risk} rule={matched_rule}")
        return decision == PolicyDecision.ALLOW
