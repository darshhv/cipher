class PolicyEngine:
    def __init__(self):
        self.allowed_pairs = set()
        self.request_counts = {}

    def allow(self, source, destination):
        self.allowed_pairs.add((source, destination))

    def risk_score(self, source, destination):
        key = (source, destination)

        count = self.request_counts.get(key, 0) + 1
        self.request_counts[key] = count

        # Simple behavioral risk model
        if count > 10:
            return 0.9
        elif count > 5:
            return 0.6
        else:
            return 0.1

    def is_allowed(self, source, destination):
        if (source, destination) not in self.allowed_pairs:
            return False

        risk = self.risk_score(source, destination)

        print(f"[Policy] Risk score: {risk}")

        return risk < 0.8
