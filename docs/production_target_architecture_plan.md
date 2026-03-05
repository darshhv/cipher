# Cipher Production-Grade Target Architecture Plan

> Execution follow-up: see `docs/next_90_day_execution_plan.md` for sprint-level delivery sequencing and acceptance criteria.

## 1) Objective

Evolve Cipher from a functional prototype into a production-grade zero-trust security platform for microservices, with strong guarantees across security, reliability, scalability, observability, and operability.

## 2) Current-State Summary (as implemented)

- Local file-backed CA with root and service certificate issuance.
- Minimal FastAPI CA server with unauthenticated issuance endpoints.
- Simple allowlist policy engine with request-count risk scoring.
- SQLite-based telemetry persistence.
- Basic proxy orchestration and certificate rotation loop.

This is a good prototype baseline, but it lacks hardening and distributed-system capabilities required for production deployments.

## 3) Target Architecture (Production)

### 3.1 Planes and Core Services

#### Control Plane

1. **Identity & PKI Service**
   - Offline root CA + online intermediate CAs.
   - HSM/KMS-backed key operations (no plaintext private keys on disk).
   - Certificate issuance, renewal, revocation, and policy-bound identity constraints.
   - Multi-tenant trust domain support.

2. **Enrollment & Attestation Service**
   - Bootstrap tokens with strict TTL/audience/scope.
   - Workload attestation via Kubernetes SA/JWT, node identity, or cloud identity.
   - CSR validation and issuance approval workflow.

3. **Policy Control Service**
   - Versioned policy bundles with signed distribution.
   - Fine-grained RBAC/ABAC conditions (source, destination, method, path, claims).
   - Staged rollout/canary policy deployment and automatic rollback.

4. **Telemetry, Audit, and Analytics Service**
   - Structured security event ingestion (queue-based).
   - Tamper-evident audit trail and retention controls.
   - Near real-time detection for anomalies and policy violations.

5. **Control Plane API Gateway**
   - Authenticated and authorized API surface.
   - Rate limiting, quotas, request signing, and mTLS.

#### Data Plane

1. **Sidecar/Node Proxy Runtime**
   - Mandatory mTLS for service-to-service traffic.
   - Local policy cache and fail-safe behavior.
   - Cert hot-reload and connection draining.

2. **Local Agent**
   - Handles enrollment, cert refresh, and secure storage interaction.
   - Health/status reporting to control plane.

### 3.2 Data Stores and Messaging

- **Primary relational store** (e.g., PostgreSQL) for config, policy metadata, issuance records.
- **Event streaming bus** (e.g., Kafka/NATS) for telemetry and async workflows.
- **Object storage** for immutable policy bundles and audit exports.
- **Cache layer** (e.g., Redis) for high-read control-plane paths.

### 3.3 Trust and Crypto Model

- Offline root, short-lived intermediate certs, automated rollover.
- Service cert TTL default 12–24h, automated rotation before expiry window.
- CRL and/or OCSP support with short-lived cert strategy.
- Modern crypto defaults and algorithm agility.

## 4) Reliability and Availability Targets

### 4.1 SLOs

- Control plane API availability: 99.95%+
- Cert issuance p95 latency: < 500 ms (steady-state)
- Policy propagation p95: < 30 s
- Data plane authorization decision p99: < 10 ms (local cache hit)

### 4.2 HA/DR

- Multi-AZ control plane deployments.
- Active-active API tier with stateless services.
- Managed DB with PITR and cross-region replicas.
- Tested disaster recovery runbooks (RTO/RPO defined per tier).

## 5) Security Hardening Requirements

1. **Key Management**
   - HSM/KMS integration for CA keys.
   - Envelope encryption for all sensitive secrets at rest.

2. **API Security**
   - mTLS + workload/service authn for machine clients.
   - OIDC/JWT for human/admin access.
   - Fine-grained authorization and full audit logging.

3. **Supply Chain Security**
   - Signed images (Sigstore/cosign).
   - SBOM generation and vulnerability gating in CI.
   - Provenance attestation (SLSA-aligned).

4. **Runtime Security**
   - Least-privilege containers, read-only rootfs, seccomp/AppArmor.
   - Egress controls and network policy enforcement.

## 6) Observability and Operations

- OpenTelemetry traces/metrics/logs end-to-end.
- SLI dashboards: issuance success, rotation health, policy error rate, deny spikes.
- Alerting on cert expiry risk, issuance anomalies, control-plane degradation.
- Admin tooling: policy diff, rollout status, cert inventory, compliance reports.

## 7) Compliance and Governance

- Audit event schema aligned to SOC2/HIPAA/PCI evidence expectations.
- Immutable export pipelines and retention/legal hold controls.
- Change management workflow for policy and identity templates.
- Periodic access review and key ceremony procedures.

## 8) Phased Implementation Roadmap

### Phase 0: Foundation Stabilization (2–4 weeks)

- Align docs with implemented behavior.
- Add comprehensive tests (unit/integration/e2e) and CI quality gates.
- Introduce typed config model and explicit startup validation.

**Exit criteria:** deterministic local/dev runs, baseline CI green, architectural docs current.

### Phase 1: Security Baseline (4–8 weeks)

- Enforce authenticated CA API (mTLS or signed token flow).
- Introduce intermediate CA model and key custody abstraction.
- Replace plaintext key persistence with secure secret backend abstraction.

**Exit criteria:** authenticated issuance only, key material protected, issuance audit complete.

### Phase 2: Control Plane Hardening (6–10 weeks)

- Move telemetry/config state to PostgreSQL + queue.
- Add RBAC for admin and service operations.
- Build policy versioning, signed bundles, and staged rollout.

**Exit criteria:** HA-capable control plane, safe policy rollout, persistent auditable state.

### Phase 3: Data Plane Maturity (6–10 weeks)

- Production proxy runtime integration (or hardened in-house runtime).
- Local policy cache with fallback semantics and TTL/consistency controls.
- Zero-downtime certificate rotation and robust failure handling.

**Exit criteria:** resilient data plane under control-plane outages.

### Phase 4: Enterprise Readiness (8–12 weeks)

- Compliance reporting pipeline and immutable evidence export.
- Multi-region DR and failover validation.
- Performance/scalability tuning with load-test signoff.

**Exit criteria:** production SLO attainment, compliance evidence generation, DR signoff.

## 9) Suggested Repository-Level Refactor Plan

1. Split into clear packages/services:
   - `cipher/control_plane/{identity,policy,telemetry,api}`
   - `cipher/data_plane/{proxy,agent}`
   - `cipher/common/{config,crypto,auth,events}`

2. Introduce interface boundaries:
   - `KeyStore`, `CertificateStore`, `PolicyStore`, `EventSink`, `IdentityAttestor`.

3. Add migrations and schema management for persistent stores.

4. Add dedicated test layout:
   - `tests/unit`, `tests/integration`, `tests/e2e`, `tests/security`.

## 10) Risks and Mitigations

- **Risk:** Overbuilding before validating adoption.
  - **Mitigation:** ship in phases with customer-driven milestones.

- **Risk:** PKI complexity and operational burden.
  - **Mitigation:** start with managed KMS/HSM and explicit key lifecycle runbooks.

- **Risk:** Policy regressions causing outages.
  - **Mitigation:** staged rollout, dry-run mode, and automated rollback criteria.

## 11) First 30-Day Action Plan

1. Add authenticated enrollment/issuance and remove unauthenticated cert issuance.
2. Replace SQLite telemetry path with abstraction and PostgreSQL implementation.
3. Expand policy engine to structured rules + deterministic tests.
4. Introduce OTel instrumentation and baseline SLI dashboard.
5. Publish operations runbook: bootstrap, rotation, incident response.

---

This plan is intentionally sequenced to deliver immediate risk reduction first (authn/authz + key custody), then reliability and scale, then compliance and enterprise controls.
