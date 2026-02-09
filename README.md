# Cipher - Zero-Trust Security Mesh for Microservices

A production-grade distributed security platform that provides identity-based authentication, policy-driven authorization, and cryptographically verified service-to-service communication for microservices environments.

## Overview

Cipher implements a complete zero-trust security mesh with control-plane and data-plane architecture, enabling organizations to secure microservice communication through mutual TLS (mTLS), behavioral risk scoring, and comprehensive audit logging. The system is designed for Kubernetes environments and compliance-focused organizations requiring SOC2, HIPAA, or PCI-DSS controls.

**Key Capabilities:**
- Certificate Authority with SPIFFE-based workload identities
- Automated certificate lifecycle management and rotation
- Sidecar proxy enforcement with transparent mTLS
- Policy-based authorization with behavioral risk scoring
- Security telemetry and compliance-ready audit logging
- HTTP-based control plane API for distributed deployment

## Architecture

Cipher separates security concerns into control-plane and data-plane components:

```
┌─────────────────────────────────────────────────────────────┐
│                      CONTROL PLANE                           │
│  ┌──────────────────┐  ┌─────────────────┐  ┌─────────────┐│
│  │ Certificate      │  │ Policy Engine   │  │ Telemetry & ││
│  │ Authority (CA)   │  │ - Risk Scoring  │  │ Audit Log   ││
│  │ - Identity Mgmt  │  │ - Authorization │  │ - Events    ││
│  │ - HTTP API       │  │ - Behavioral    │  │ - Metrics   ││
│  └──────────────────┘  └─────────────────┘  └─────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
                            │ mTLS + Identity
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       DATA PLANE                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Service A               Service B                     │ │
│  │  ┌───────────┐          ┌───────────┐                 │ │
│  │  │   App     │          │   App     │                 │ │
│  │  └─────┬─────┘          └─────┬─────┘                 │ │
│  │  ┌─────▼─────┐          ┌─────▼─────┐                 │ │
│  │  │  Sidecar  │◄────────►│  Sidecar  │                 │ │
│  │  │  Proxy    │   mTLS   │  Proxy    │                 │ │
│  │  └───────────┘          └───────────┘                 │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Control Plane:**
- Manages service identity and certificate issuance
- Evaluates authorization policies with risk scoring
- Collects security telemetry and audit events
- Exposes HTTP API for service enrollment

**Data Plane:**
- Sidecar proxies enforce mTLS on all service communication
- Validates certificates and extracts SPIFFE identities
- Forwards telemetry to control plane
- Performs local policy caching and enforcement

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/darshhv/cipher.git
cd cipher

# Install as editable package
pip install -e .

# Verify installation
cipher-cli --help
```

### Initialize Certificate Authority

```bash
# Initialize CA and generate root certificate
cipher-cli init

# Output:
# Initializing Certificate Authority...
# Root CA created at: data/ca/root_ca.crt
# Certificate Authority initialized successfully
```

### Enroll Services

```bash
# Enroll services and issue certificates
cipher-cli enroll payment-api
cipher-cli enroll user-service

# Each service receives:
# - Private key (2048-bit RSA)
# - Certificate with SPIFFE identity
# - Root CA certificate for validation
```

### Start Control Plane

```bash
# Start CA HTTP API server
cipher-cli ca-server

# Control plane listens on http://localhost:8000
# Endpoints:
#   POST /v1/certificate - Issue service certificate
#   GET /v1/ca/cert - Retrieve root CA certificate
```

### Run Demo

```bash
# Execute end-to-end demonstration
cipher-cli demo

# Demonstrates:
# - Certificate validation
# - mTLS communication
# - Policy evaluation
# - Risk scoring (burst detection)
# - Telemetry logging
```

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

server:
  host: 0.0.0.0
  port: 8000
  enable_tls: false
```

Configuration file location can be specified via:
```bash
cipher-cli --config /path/to/config.yaml <command>
```

## Features

### Certificate Authority

**Identity Management:**
- Self-signed root CA with configurable key size (default 4096-bit RSA)
- Service certificates with SPIFFE URI identities
- Format: `spiffe://cipher.local/service/<service-name>`
- Short-lived certificates (24-hour default, configurable)

**Certificate Properties:**
- Root CA: 10-year validity, BasicConstraints CA=true
- Service Certs: 24-hour validity, mTLS extensions (serverAuth, clientAuth)
- Automatic serial number generation
- SHA256 signature algorithm

**HTTP API Endpoints:**
```bash
POST /v1/certificate
  Body: { "service_identity": "payment-api", "csr_pem": "..." }
  Returns: { "certificate_pem": "...", "root_ca_pem": "...", "spiffe_id": "..." }

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

**Example Policy Rule:**
```python
PolicyRule(
    name="allow-payment-to-database",
    source_identity="spiffe://cipher.local/service/payment-api",
    destination_identity="spiffe://cipher.local/service/database",
    method="GET",
    path_pattern="/api/*",
    action=PolicyDecision.ALLOW,
    priority=10
)
```

### Sidecar Proxy

**Transparent mTLS Enforcement:**
- Intercepts inbound requests and validates client certificates
- Extracts SPIFFE identity from certificate SAN
- Evaluates policies before forwarding to upstream service
- Injects identity headers for application-level authorization

**Proxy Capabilities:**
- Client certificate validation against root CA
- Certificate chain verification
- TLS 1.2+ enforcement
- Configurable upstream routing
- Request/response telemetry forwarding

**Certificate Hot-Reload:**
- Monitors certificate files for updates
- Reloads SSL contexts without connection drops
- Maintains existing connections during rotation
- Zero-downtime certificate renewal

### Security Telemetry

**Event Logging:**
The telemetry system records all security-relevant events:

- Authentication success/failure
- Authorization decisions (allow/deny/throttle)
- Certificate operations (issuance, renewal, revocation)
- Policy violations
- Anomaly detections
- Risk score distributions

**Storage:**
- SQLite database for persistent audit trail
- Structured event schema with indexed queries
- Configurable retention policies
- In-memory metrics for real-time dashboards

**Compliance Reporting:**
```python
# Generate compliance report
telemetry.generate_compliance_report(hours=24)

# Returns:
# - Total events by type
# - Authentication success rate
# - Authorization success rate
# - High-risk event count
# - Top source identities
# - Failed access attempts
```

**Query Interface:**
```python
# Query security events
events = telemetry.query_events(
    event_type=EventType.AUTHORIZATION_FAILURE,
    source_identity="spiffe://cipher.local/service/payment-api",
    start_time="2024-02-10T00:00:00Z",
    limit=100
)
```

## Technical Implementation

### SPIFFE Identity Format

Services are identified using SPIFFE URIs embedded in X.509 certificate Subject Alternative Names:

```
spiffe://cipher.local/service/payment-api
spiffe://cipher.local/service/user-service
spiffe://cipher.local/service/database
```

The trust domain (`cipher.local`) is configurable and should be unique per deployment.

### Certificate Chain Validation

Cipher validates certificates through multi-step verification:

1. **Signature Verification**: Validate certificate signed by root CA
2. **Expiration Check**: Ensure certificate is within validity period
3. **Chain Verification**: Verify issuer matches root CA subject
4. **Extension Validation**: Check KeyUsage and ExtendedKeyUsage
5. **Identity Extraction**: Parse SPIFFE URI from SAN extension

### mTLS Communication Flow

```
Client Service                   Sidecar Proxy                   Server Service
      │                                │                                │
      │  1. Outbound Request           │                                │
      ├───────────────────────────────>│                                │
      │                                │  2. TLS Handshake              │
      │                                │  - Present client cert         │
      │                                ├───────────────────────────────>│
      │                                │  3. Validate server cert       │
      │                                │<───────────────────────────────┤
      │                                │  4. Mutual authentication      │
      │                                │<──────────────────────────────>│
      │                                │  5. Policy evaluation          │
      │                                │  - Extract client identity     │
      │                                │  - Check authorization         │
      │                                │  - Compute risk score          │
      │                                │                                │
      │                                │  6. Forward request            │
      │                                ├───────────────────────────────>│
      │                                │  7. Response                   │
      │  8. Return to client           │<───────────────────────────────┤
      │<───────────────────────────────┤                                │
      │                                │  9. Log telemetry              │
```

### Certificate Rotation Mechanism

Rotation manager runs in background thread:

```python
while running:
    if certificate.expires_in < (total_lifetime * 0.5):
        # Generate new CSR
        csr = generate_csr(service_identity)
        
        # Request new certificate from CA
        new_cert = ca_client.renew_certificate(csr)
        
        # Atomically replace credentials
        save_certificate(new_cert)
        save_private_key(new_key)
        
        # Reload SSL contexts
        proxy.reload_certificates()
        
    sleep(60)  # Check every minute
```

## Use Cases

### Kubernetes Security

Deploy Cipher as a sidecar container alongside application pods:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payment-api
spec:
  containers:
  - name: payment-api
    image: payment-api:latest
    ports:
    - containerPort: 8080
  
  - name: cipher-proxy
    image: cipher-proxy:latest
    env:
    - name: SERVICE_IDENTITY
      value: payment-api
    - name: CA_API_URL
      value: http://cipher-ca:8000
    ports:
    - containerPort: 8443
```

### SOC2/HIPAA Compliance

Cipher provides audit controls required for compliance:

**Access Control:**
- Cryptographic identity for all services
- Certificate-based authentication (no static credentials)
- Policy-based authorization with deny-by-default

**Encryption:**
- All service-to-service traffic encrypted via mTLS
- TLS 1.2+ enforcement
- Strong cipher suites (AES-256, SHA256)

**Audit Logging:**
- Complete audit trail of authentication events
- Authorization decisions with risk scores
- Tamper-evident SQLite storage
- Configurable retention policies

**Example Compliance Report:**
```
Summary (24 hours):
  Total Events: 1,247
  Authentication Success Rate: 99.8%
  Authorization Success Rate: 96.3%
  High Risk Events: 12
  
Top Source Identities:
  spiffe://cipher.local/service/payment-api: 456 requests
  spiffe://cipher.local/service/user-service: 389 requests
  
Failed Authorizations:
  14:23:45 - payment-api -> admin-service - DENIED (policy violation)
  15:12:09 - external-api -> database - DENIED (risk score 0.85)
```

### Zero-Trust Architecture

Cipher enforces zero-trust principles:

**Never Trust, Always Verify:**
- No implicit trust based on network location
- Every request authenticated via certificate
- Every request authorized via policy

**Least Privilege:**
- Services granted minimal required permissions
- Policy rules specify exact source/destination pairs
- Wildcards used sparingly and explicitly

**Assume Breach:**
- Short-lived certificates (24-hour default)
- Behavioral anomaly detection
- Complete audit trail for forensics

## Development

### Project Structure

```
cipher/
├── cipher/
│   ├── ca/
│   │   ├── certificate_authority.py    # Root CA and cert issuance
│   │   ├── control_plane_api.py        # HTTP API endpoints
│   │   └── bootstrap_tokens.py         # JWT-based enrollment tokens
│   ├── proxy/
│   │   └── sidecar_proxy.py           # mTLS enforcement and rotation
│   ├── policy/
│   │   └── policy_engine.py           # Authorization and risk scoring
│   ├── telemetry/
│   │   └── audit_logging.py           # Event logging and metrics
│   ├── services/
│   │   ├── cert_validator.py          # Certificate validation
│   │   ├── secure_client.py           # mTLS client wrapper
│   │   └── secure_server.py           # mTLS server wrapper
│   └── config/
│       └── config_loader.py           # Configuration management
├── cipher_cli.py                       # Command-line interface
├── setup.py                            # Package installation
├── cipher-config.yaml                  # Default configuration
└── data/                               # Certificate and database storage
```

### Running Tests

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run test suite
pytest tests/

# Run with coverage
pytest --cov=cipher tests/

# Test specific component
pytest tests/test_certificate_authority.py
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/darshhv/cipher.git
cd cipher

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run demo to verify installation
cipher-cli demo
```

## Security Considerations

### Current Implementation

**Production-Ready Features:**
- Strong cryptography (RSA 2048/4096, SHA256)
- Certificate chain validation
- Short-lived certificates with rotation
- Audit logging with retention policies
- Policy-based authorization

**Development/Demo Limitations:**
- Private keys stored unencrypted on disk
- No certificate revocation (CRL/OCSP)
- SQLite audit database (not distributed)
- Single-instance CA (no high availability)
- HTTP API without authentication (demo only)

### Production Deployment Requirements

**For production environments, implement:**

**Secret Management:**
- Encrypt private keys at rest (AES-256)
- Use Hardware Security Module (HSM) for CA private key
- Integrate with secrets manager (HashiCorp Vault, AWS Secrets Manager)

**Certificate Revocation:**
- Implement Certificate Revocation Lists (CRL)
- Add Online Certificate Status Protocol (OCSP) responder
- Short certificate validity as revocation mitigation

**High Availability:**
- Deploy CA in active-passive configuration
- Replicate audit database (PostgreSQL, MySQL)
- Load balance control plane API
- Implement CA key escrow and recovery procedures

**Network Security:**
- Enable TLS on CA API endpoints
- Implement API authentication (mutual TLS or tokens)
- Rate limiting on certificate issuance
- DDoS protection on control plane

**Monitoring:**
- Export metrics to Prometheus/Grafana
- Alert on high-risk events
- Track certificate expiration
- Monitor CA availability

## Consulting Services

Cipher is maintained by Darshan Reddy V, offering security architecture and implementation consulting.

**Services Available:**
- Zero-trust architecture assessment and design
- Service mesh implementation and deployment
- Compliance automation (SOC2, HIPAA, PCI-DSS)
- Custom policy development and risk scoring
- Kubernetes security hardening
- Security incident response and forensics

**Project-Based Pricing:**
- Zero-Trust Assessment: $10,000 - $15,000
- Service Mesh Implementation: $20,000 - $40,000
- Compliance Automation: $25,000 - $50,000
- Custom Policy Development: $8,000 - $15,000

**Hourly Consulting:**
- Standard Rate: $250/hour
- Senior Rate: $350/hour

**Target Clients:**
- Series A-D startups (50-500 employees)
- Organizations using Kubernetes and microservices
- Companies pursuing SOC2, HIPAA, or PCI-DSS compliance
- Fintech, healthcare, and SaaS platforms

**Contact:**
- Email: dharsxn46@gmail.com
- GitHub: https://github.com/darshhv
- LinkedIn: https://www.linkedin.com/in/darsh6/

## Contributing

Cipher is an open-source project. Contributions are welcome via pull requests.

**Development Guidelines:**
- Follow existing code structure and style
- Add tests for new features
- Update documentation for API changes
- Run full test suite before submitting PR

**Areas for Contribution:**
- Kubernetes operator implementation
- gRPC protocol support
- Additional policy rule types
- Performance optimizations
- Integration with service meshes (Istio, Linkerd)

## License

MIT License

Copyright (c) 2024 Darshan Reddy V

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

**Built with:** Python, cryptography, X.509 certificates, SPIFFE, mTLS

**Author:** Darshan Reddy V

**Repository:** https://github.com/darshhv/cipher
