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

`CIPHER_ENV` behavior:
- `dev`, `development`, `test`: allows dev defaults.
- any other value (for example `prod`, `staging`): CA startup fails if insecure defaults are still configured.

---

## Quick Start

### 1) Initialize CA

```bash
cipher-cli init
```

### 2) Start CA API server

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

Run auth-flow tests:

```bash
pytest tests/test_ca_auth_flow.py
```

---

## Notes

This repository is currently a prototype implementation. The docs in `docs/production_target_architecture_plan.md` and `docs/next_90_day_execution_plan.md` describe a production-hardening roadmap.
