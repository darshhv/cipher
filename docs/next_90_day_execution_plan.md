# Cipher: Next 90-Day Production Execution Plan

This document translates the target architecture roadmap into implementation-ready work.

## Goal for the Next 90 Days

Deliver a secure, testable, and operable baseline suitable for pilot workloads by completing:

1. Authenticated certificate issuance.
2. Hardened key handling abstraction.
3. Deterministic policy engine behavior with tests.
4. Postgres-backed telemetry and migration path from SQLite.
5. Baseline observability and runbooks.

---

## Workstream A — Authenticated Enrollment + Issuance (Weeks 1–3)

### Scope

- Replace unauthenticated `POST /v1/certificate` with authenticated enrollment + issuance flow.
- Add short-lived bootstrap tokens with scope (`service_name`), audience (`cipher-ca`), and TTL.
- Require token validation before certificate issuance.

### Deliverables

- New endpoints:
  - `POST /v1/enroll/token` (admin-auth only)
  - `POST /v1/certificate` (requires valid bootstrap token)
- Token validator module with strict claim verification.
- Audit events for token mint/use/failure.

### Acceptance Criteria

- Issuance fails without token.
- Issuance fails for expired/invalid-audience/scope-mismatch token.
- Successful issuance logs structured audit event.
- Unit + API integration tests cover success and failure paths.

---

## Workstream B — Key Management Abstraction (Weeks 2–4)

### Scope

- Introduce key custody interface to remove direct plaintext key assumptions from business logic.
- Start with file-based provider + KMS-ready interface.

### Deliverables

- Interface definitions:
  - `KeyStore`
  - `CertificateStore`
- Providers:
  - `FileKeyStore` (current behavior)
  - `FileCertificateStore`
- CA issuance code refactored to use interfaces.

### Acceptance Criteria

- CA logic no longer directly writes private keys outside store abstraction.
- Swappable provider contract validated through unit tests.
- Existing CLI workflows continue to function.

---

## Workstream C — Policy Engine v2 (Weeks 3–6)

### Scope

- Move from pair allowlist to deterministic rule model.
- Introduce explicit decision outcomes: `ALLOW`, `DENY`, `THROTTLE`.

### Deliverables

- Rule schema:
  - source identity matcher
  - destination matcher
  - method matcher
  - path matcher
  - priority
  - action
- Evaluation order and default-deny semantics.
- Risk score as separate signal from static rule match.

### Acceptance Criteria

- Rule priority behavior is deterministic and tested.
- Deny-by-default is enforced.
- At least 20 policy unit tests including edge/conflict cases.

---

## Workstream D — Telemetry Storage Migration (Weeks 4–7)

### Scope

- Decouple telemetry from direct SQLite calls.
- Add Postgres backend and migration plan.

### Deliverables

- `EventSink` interface.
- `SQLiteEventSink` (backward compatibility).
- `PostgresEventSink` (new default for production profile).
- DB migration scripts and schema versioning.

### Acceptance Criteria

- Both sinks pass shared contract tests.
- Config selects sink without code changes.
- Event writes include structured fields for authn/authz/cert lifecycle.

---

## Workstream E — Observability + Operability (Weeks 6–9)

### Scope

- Introduce baseline metrics/tracing and operational playbooks.

### Deliverables

- Metrics:
  - certificate issuance success/failure counts
  - issuance latency histogram
  - policy decision counters
  - rotation renewal counters
- Trace instrumentation for CA request path.
- Runbooks:
  - CA bootstrap
  - certificate rotation troubleshooting
  - incident triage for deny spikes

### Acceptance Criteria

- `/metrics` endpoint available for control plane.
- Core flows emit traces with request correlation IDs.
- Runbooks validated via tabletop exercise.

---

## Recommended Repository Tasks

1. Create new module layout:
   - `cipher/control_plane/identity`
   - `cipher/control_plane/policy`
   - `cipher/control_plane/telemetry`
   - `cipher/common/interfaces`
2. Add test directories:
   - `tests/unit`
   - `tests/integration`
   - `tests/contracts`
3. Add CI gates:
   - lint
   - unit tests
   - integration tests
   - security checks (`pip-audit`)

---

## Sprint-Level Milestone Plan

### Sprint 1 (2 weeks)

- Authenticated issuance MVP.
- Token verification tests.
- Basic issuance audit events.

**Milestone check:** unauthenticated cert issuance path removed.

### Sprint 2 (2 weeks)

- KeyStore/CertificateStore abstractions integrated.
- Policy engine v2 rule model introduced.

**Milestone check:** deterministic policy tests green.

### Sprint 3 (2 weeks)

- Postgres event sink + migrations.
- Metrics and tracing baseline.

**Milestone check:** production profile runs with Postgres + metrics.

### Sprint 4 (2 weeks)

- Hardening/cleanup, runbooks, and pilot readiness validation.

**Milestone check:** pilot checklist complete.

---

## Pilot Readiness Checklist

- [ ] All CA issuance endpoints authenticated.
- [ ] Cert issuance and policy decisions fully auditable.
- [ ] Rotation path tested under failure conditions.
- [ ] Postgres telemetry path stable under load test.
- [ ] Runbooks published and reviewed.
- [ ] CI quality gates enforced on every PR.

---

## Definition of Done (for this 90-day plan)

A deployable control-plane baseline that supports authenticated issuance, deterministic policy enforcement, durable telemetry, and observable operations with documented incident response procedures.
