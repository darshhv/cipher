# Cipher

A Python prototype for zero-trust service identity and authenticated certificate issuance.

Cipher currently provides:
- Root CA initialization and service certificate issuance.
- Authenticated enrollment using admin-minted bootstrap JWT tokens.
- SPIFFE identity embedding in service certificates.
- Basic policy, proxy, and telemetry demo components.

---

## Current Architecture (Implemented)

### Control Plane
- **CA service** (`cipher/ca/certificate_authority.py`):
  - Initializes root CA key/cert.
  - Issues service certificates under `data/<service>/`.
- **CA API** (`cipher/ca/ca_server.py`):
  - `POST /v1/enroll/token` (requires `X-Admin-Token`).
  - `POST /v1/certificate` (requires bootstrap token).
  - `GET /v1/ca/cert` (returns root CA cert).
- **Bootstrap token manager** (`cipher/ca/bootstrap_tokens.py`):
  - Mints and validates HS256 JWT bootstrap tokens.

### Data Plane / Runtime Components
- **Certificate validator** (`cipher/services/cert_validator.py`) validates chain and extracts SPIFFE URI.
- **Policy engine** (`cipher/policy/policy_engine.py`) provides deterministic rules (priority/action/path/method), risk scoring, and deny-by-default fallback.
- **Policy engine** (`cipher/policy/policy_engine.py`) provides basic allowlist + risk-threshold logic.
- **Telemetry** (`cipher/telemetry/audit_logging.py`) logs events to SQLite.
- **Proxy/server demos** in `cipher/proxy/` and `cipher/services/`.

---

## Repository Layout

```text
cipher/
├── cipher/
│   ├── ca/
│   ├── policy/
│   ├── proxy/
│   ├── services/
│   ├── telemetry/
│   └── config.py
├── docs/
├── tests/
├── cipher_cli.py
├── cipher-config.yaml
├── requirements.txt
└── setup.py
```

---

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

CLI entrypoint:

```bash
cipher-cli --help
```

---

## Configuration

Cipher reads `cipher-config.yaml`.

Important API auth settings:

```yaml
api:
  admin_token: dev-admin-token-change-me
  token_secret: dev-insecure-secret-change-me
  token_issuer: cipher-ca
  token_audience: cipher-ca
  token_ttl_seconds: 300
```

Environment overrides supported by CA API:
- `CIPHER_ADMIN_TOKEN`
- `CIPHER_TOKEN_SECRET`
- `CIPHER_TOKEN_ISSUER`
- `CIPHER_TOKEN_AUDIENCE`
- `CIPHER_TOKEN_TTL_SECONDS`
- `CIPHER_ENV`
- `CIPHER_CA_URL` (CLI only, default `http://127.0.0.1:9000`)

```bash
# (Required) set admin token used to mint bootstrap tokens
export CIPHER_ADMIN_TOKEN=dev-admin-token-change-me

# Enroll services and issue certificates
cipher-cli enroll payment-api
cipher-cli enroll user-service

Cipher reads `cipher-config.yaml`.

Important API auth settings:

```yaml
api:
  admin_token: dev-admin-token-change-me
  token_secret: dev-insecure-secret-change-me
  token_issuer: cipher-ca
  token_audience: cipher-ca
  token_ttl_seconds: 300
```

Environment overrides supported by CA API:
- `CIPHER_ADMIN_TOKEN`
- `CIPHER_TOKEN_SECRET`
- `CIPHER_TOKEN_ISSUER`
- `CIPHER_TOKEN_AUDIENCE`
- `CIPHER_TOKEN_TTL_SECONDS`
- `CIPHER_ENV`

`CIPHER_ENV` behavior:
- `dev`, `development`, `test`: allows dev defaults.
- any other value (for example `prod`, `staging`): CA startup fails if insecure defaults are still configured.

---
# Control plane listens on http://127.0.0.1:9000
# Endpoints:
#   POST /v1/enroll/token - Mint bootstrap token (requires X-Admin-Token)
#   POST /v1/certificate - Issue service certificate (requires bootstrap token)
#   GET /v1/ca/cert - Retrieve root CA certificate
```

## Quick Start

### 1) Initialize CA

```bash
cipher-cli init
```

### 2) Start CA API server
## Configuration

Cipher uses `cipher-config.yaml` for system configuration:

```yaml
ca:
  trust_domain: cipher.local
  root_key_size: 4096
  service_key_size: 2048
  cert_validity_hours: 24
  ca_cert_validity_years: 10

policy:
  risk_threshold_deny: 0.8
  risk_threshold_throttle: 0.6
  burst_detection_window_seconds: 60
  frequency_tracking_window_seconds: 300

telemetry:
  database_path: ./data/cipher_audit.db
  log_level: INFO
  retention_days: 90

api:
  admin_token: dev-admin-token-change-me
  token_secret: dev-insecure-secret-change-me
  token_issuer: cipher-ca
  token_audience: cipher-ca
  token_ttl_seconds: 300

# Optional env overrides:
#   CIPHER_ADMIN_TOKEN
#   CIPHER_TOKEN_SECRET
#   CIPHER_TOKEN_ISSUER
#   CIPHER_TOKEN_AUDIENCE
#   CIPHER_TOKEN_TTL_SECONDS
#   CIPHER_ENV (set to prod/staging to block insecure defaults)
```

```bash
cipher-cli ca-server
```

Server binds to `127.0.0.1:9000`.

### 3) Enroll a service (authenticated flow)

Set admin token (for local default config):

```bash
export CIPHER_ADMIN_TOKEN=dev-admin-token-change-me
```

Enroll:

POST /v1/enroll/token
  Headers: X-Admin-Token: <admin-token>
  Body: { "service_name": "payment-api" }
  Returns: { "service_name": "payment-api", "bootstrap_token": "..." }

POST /v1/certificate
  Body: { "service_name": "payment-api", "bootstrap_token": "..." }
  Returns: { "issued": "payment-api" }

GET /v1/ca/cert
  Returns: Root CA certificate in PEM format
```

### Certificate Rotation

**Automated Lifecycle Management:**
- Background rotation manager monitors certificate expiration
- Automatic renewal when 50% of certificate lifetime remains
- Hot-reload of certificates without service restart
- Configurable renewal thresholds

**Rotation Process:**
1. Monitor certificate expiration in background thread
2. Generate new CSR when renewal threshold reached
3. Request new certificate from CA API
4. Atomically replace certificate and private key
5. Reload SSL contexts in running proxies

### Policy Engine

**Authorization Framework:**
- Rule-based policies with pattern matching
- Source/destination identity matching with wildcards
- HTTP method and path filtering
- Priority-based rule evaluation

**Behavioral Risk Scoring:**
The policy engine computes risk scores based on four factors:

1. **Request Frequency** (30% weight)
   - Tracks requests per identity over 5-minute window
   - Low volume: 0.0-0.1 risk
   - High volume (100+ requests): 0.9 risk

2. **New Destination Detection** (20% weight)
   - Identifies first-time service-to-service communication
   - Known destinations: 0.0 risk
   - New destinations: 0.4 risk

3. **Unusual Method Usage** (20% weight)
   - Analyzes HTTP method distribution per identity
   - Common methods (>50% usage): 0.0 risk
   - Rare methods (<10% usage): 0.5 risk

4. **Burst Detection** (30% weight)
   - Monitors requests in 60-second sliding window
   - Normal load (<10 requests): 0.0 risk
   - Burst (30+ requests): 0.8 risk

**Decision Logic:**
```
Total Risk = Weighted Average of Factors

if risk >= 0.8:
    decision = DENY
elif risk >= 0.6:
    decision = THROTTLE
else:
    decision = ALLOW
```

Enroll:

```bash
cipher-cli enroll payment-api
```

This performs:
1. `POST /v1/enroll/token` with `X-Admin-Token`.
2. `POST /v1/certificate` with `{service_name, bootstrap_token}`.

### 4) Run demo

```bash
cipher-cli demo
```

---

## API Reference

### `GET /`
Returns service status.

### `GET /v1/ca/cert`
Returns root CA certificate PEM.

### `POST /v1/enroll/token`
Request bootstrap token for one service identity.

Headers:
- `X-Admin-Token: <admin-token>`

Body:
```json
{ "service_name": "payment-api" }
```

Response:
```json
{ "service_name": "payment-api", "bootstrap_token": "..." }
```

### `POST /v1/certificate`
Issue service certificate using bootstrap token.

Body:
```json
{ "service_name": "payment-api", "bootstrap_token": "..." }
```

Response:
```json
{ "issued": "payment-api" }
```

---

## Testing

Run full test suite:

```bash
pytest -q
```

CI quality gates are defined in `.github/workflows/ci.yml` and run compile checks, tests, and an informational dependency audit.

Run auth-flow tests:

```bash
pytest tests/test_ca_auth_flow.py
```

---

## Notes

This repository is currently a prototype implementation. The docs in `docs/production_target_architecture_plan.md` and `docs/next_90_day_execution_plan.md` describe a production-hardening roadmap.
