# Cryptography Attacks, API Security & Infrastructure Hardening — Mastery Synthesis

> **Date**: 2026-07-09
> **Sources**: 33 cybersecurity skills from the Anthropic collection (Anthropic-Cybersecurity-Skills)
> **Scope**: TLS/SSL, Certificate Management, Cryptographic Weaknesses, JWT Attacks, API Security Testing, Rate Limiting, Schema Validation, Firewall/IDS Configuration, Zero Trust Architecture, DDoS Mitigation, WAF Deployment

---

## Table of Contents

1. [TLS/SSL Assessment and Attacks](#1-tlsssl-assessment-and-attacks)
2. [Certificate Management](#2-certificate-management)
3. [Cryptographic Weaknesses](#3-cryptographic-weaknesses)
4. [JWT Algorithm Confusion](#4-jwt-algorithm-confusion)
5. [API Security Testing Methodology](#5-api-security-testing-methodology)
6. [Rate Limiting and Schema Validation](#6-rate-limiting-and-schema-validation)
7. [Firewall and IDS Configuration](#7-firewall-and-ids-configuration)
8. [Zero Trust Implementation](#8-zero-trust-implementation)
9. [DDoS Mitigation](#9-ddos-mitigation)
10. [WAF Deployment and Tuning](#10-waf-deployment-and-tuning)

---

## 1. TLS/SSL Assessment and Attacks

### 1.1 TLS 1.3 Configuration (RFC 8446)

**Key improvements over TLS 1.2:**
- **1-RTT handshake** (vs 2 in TLS 1.2), **0-RTT for resumed sessions**
- **Mandatory Perfect Forward Secrecy** — no RSA key exchange allowed
- **Encrypted handshake** — server certificate encrypted after ServerHello
- Removed CBC, RC4, 3DES, static RSA, SHA-1 cipher suites

**TLS 1.3 Cipher Suites:**
| Cipher Suite | Key Exchange | Encryption | Hash |
|---|---|---|---|
| TLS_AES_256_GCM_SHA384 | ECDHE/DHE | AES-256-GCM | SHA-384 |
| TLS_AES_128_GCM_SHA256 | ECDHE/DHE | AES-128-GCM | SHA-256 |
| TLS_CHACHA20_POLY1305_SHA256 | ECDHE/DHE | ChaCha20-Poly1305 | SHA-256 |

**Preferred key exchange groups**: x25519 (fast), secp256r1, secp384r1, x448

**Critical Security Considerations:**
- 0-RTT data is vulnerable to **replay attacks** — limit to idempotent requests
- Always include TLS 1.2 fallback if legacy client support required
- Use **ECDSA certificates** for better performance vs RSA
- Enable **OCSP stapling** for certificate validation
- Set **HSTS header** with long max-age and includeSubDomains
- Monitor for certificate transparency logs

**Validation criteria:**
- [ ] Only approved cipher suites offered
- [ ] PFS enforced
- [ ] TLS 1.0/1.1 rejected
- [ ] testssl.sh reports no vulnerabilities

### 1.2 SSL/TLS Security Assessment with sslyze

**Assessment methodology using sslyze Python library:**
1. Create `ServerScanRequest` with `ServerNetworkLocation` (hostname, port 443)
2. Execute concurrent scans for all TLS check commands
3. Evaluate: supported protocols (SSLv2/3, TLS 1.0-1.3), cipher suite strength, certificate chain validation, HSTS enforcement, OCSP stapling
4. Scan for known vulnerabilities: **Heartbleed**, **ROBOT**, session renegotiation weaknesses
5. Generate JSON report with compliance findings and remediation

**Key checks:**
- Certificate validity, chain completeness
- Protocol version acceptance/rejection
- HSTS header presence and configuration
- Known vulnerability exploitation results

### 1.3 SSL/TLS Inspection (Break-and-Inspect)

**Modes:**
| Mode | Direction | Description |
|---|---|---|
| SSL Forward Proxy | Outbound | Intercepts client-to-internet HTTPS |
| SSL Inbound Inspection | Inbound | Decrypts traffic to internal servers |
| SSH Proxy | Both | Inspects SSH tunneled traffic |

**Forward Proxy Process:**
```
Client → Firewall → Web Server
1. Client sends ClientHello
2. Firewall forwards to real server, receives ServerHello (real cert)
3. Firewall generates proxy cert signed by internal CA
4. Returns proxy cert to client
5. Decrypts, inspects, re-encrypts for both legs
```

**Certificate Trust Chain:**
```
Enterprise Root CA → Subordinate CA (SSL Inspection) → Dynamically Generated Server Certificates
```

**Performance impact:**
| Factor | Impact | Mitigation |
|---|---|---|
| CPU overhead | 50-80% increase | Hardware SSL acceleration |
| Throughput reduction | 40-60% typical | Size for peak encrypted traffic |
| Latency increase | 1-5ms | Place inspection close to users |
| TLS 1.3 0-RTT | Cannot inspect | Block 0-RTT or accept risk |
| QUIC/HTTP3 | Bypasses proxy | Block QUIC, force HTTP/2 |

**Best practices:**
- Start with **logging/detect-only mode** first
- Maintain **exemption list** for certificate-pinned apps
- **Block QUIC** (UDP/443) to force HTTP/2 through inspection
- Store inspection CA private key in **HSM** for production
- Plan for **CA certificate rotation** before expiration

---

## 2. Certificate Management

### 2.1 CA Hierarchy with OpenSSL

**Two-tier architecture:**
```
Root CA (offline, air-gapped)
  └── Intermediate CA (online, operational)
        ├── Server Certificates
        ├── Client Certificates
        └── Code Signing Certificates
```

**Critical certificate extensions:**
| Extension | Purpose | Critical |
|---|---|---|
| basicConstraints | CA:TRUE/FALSE, pathLenConstraint | Yes |
| keyUsage | keyCertSign, cRLSign, digitalSignature | Yes |
| extendedKeyUsage | serverAuth, clientAuth, codeSigning | No |
| subjectKeyIdentifier | Hash of public key | No |
| authorityKeyIdentifier | Issuer's key identifier | No |
| crlDistributionPoints | URL to CRL | No |
| authorityInfoAccess | OCSP responder URL | No |

**Security considerations:**
- Root CA private key stored **offline** (air-gapped HSM)
- Minimum **4096-bit RSA** or **P-384 ECDSA** for CA keys
- Set **path length constraints** on intermediate CAs
- Implement **certificate policies** (OIDs)
- Enable **CRL and OCSP** for revocation checking
- **Audit** all certificate issuance operations

### 2.2 RSA Key Pair Management

**Key sizes and security strength:**
| Key Size | Security Strength | Recommended Until |
|---|---|---|
| 2048-bit | 112-bit | 2030 |
| 3072-bit | 128-bit | Beyond 2030 |
| 4096-bit | ~140-bit | Beyond 2030 |

**RSA Padding Schemes:**
| Scheme | Use Case | Status |
|---|---|---|
| OAEP | Encryption | Recommended (PKCS#1 v2.2) |
| PSS | Signatures | Recommended (PKCS#1 v2.2) |
| PKCS#1 v1.5 | Legacy only | **Deprecated** for new systems |

**Key storage formats**: PEM (Base64), DER (binary), PKCS#8 (standard private key encapsulation), PKCS#12/PFX (bundled key + certificate)

### 2.3 Ed25519 Digital Signatures

**Ed25519 vs RSA-3072 vs ECDSA P-256:**
| Property | Ed25519 | RSA-3072 | ECDSA P-256 |
|---|---|---|---|
| Security | 128-bit | 128-bit | 128-bit |
| Public key size | 32 bytes | 384 bytes | 64 bytes |
| Signature size | 64 bytes | 384 bytes | 64 bytes |
| Key generation | ~50 μs | ~100 ms | ~1 ms |
| Sign | ~70 μs | ~5 ms | ~200 μs |
| Verify | ~200 μs | ~200 μs | ~500 μs |
| Deterministic | **Yes** | No (PSS) | No |

**Ed25519 advantages**: deterministic signatures (no random nonce needed), resistance to side-channel attacks, fast verification, small keys (32 bytes each).

### 2.4 Digital Signatures with Ed25519

- **Deterministic**: Same message + key → same signature
- **Collision-resistant**: No separate hash function needed
- **Side-channel resistant**: Constant-time implementation
- **Use case**: Document signing, code signing, API authentication

### 2.5 Post-Quantum Cryptography

The `implementing-post-quantum-cryptography-migration` skill does **not exist** in the collection. For PQC migration guidance, refer to NIST post-quantum standards (CRYSTALS-Kyber for key encapsulation, CRYSTALS-Dilithium for signatures).

---

## 3. Cryptographic Weaknesses

### 3.1 Cryptographic Audit Methodology

**Weakness categories:**
| Category | Examples | Risk |
|---|---|---|
| Weak Hashing | MD5, SHA-1 for integrity/signatures | **High** |
| Insecure Encryption | DES, 3DES, RC4, Blowfish | **High** |
| Bad Cipher Mode | ECB mode for any block cipher | **High** |
| Insufficient Key Size | RSA < 2048, AES-128 for long-term | Medium |
| Hardcoded Secrets | Keys/passwords in source code | **Critical** |
| Weak KDF | Low iteration PBKDF2, plain MD5 | **High** |
| Poor Entropy | time-based seeds, predictable IVs | **High** |
| Deprecated Protocols | SSLv3, TLS 1.0, TLS 1.1 | **High** |

**Audit scope**: Review both application code and configuration files. Check third-party dependencies. Verify certificates and TLS configurations. Ensure secrets from environment variables or vaults. Review key storage and rotation practices.

### 3.2 AES Encryption for Data at Rest

**AES modes of operation:**
| Mode | Authentication | Parallelizable | Use Case |
|---|---|---|---|
| GCM | Yes (AEAD) | Yes | Network data, file encryption |
| CBC | No | Decrypt only | Legacy, disk encryption |
| CTR | No | Yes | Streaming encryption |
| CCM | Yes (AEAD) | No | IoT, constrained environments |

**Encrypted file format**: `[salt: 16 bytes][nonce: 12 bytes][ciphertext: variable][tag: 16 bytes]`

**Critical rules:**
- **Never reuse a nonce** with the same key (catastrophic in GCM)
- Always use **authenticated encryption** (GCM, CCM)
- Use at least **256-bit keys** for long-term data protection
- Generate nonces using **CSPRNG** (`os.urandom()`)
- Store nonce alongside ciphertext (not secret)

**Key derivation**: Never use raw passwords. Use **PBKDF2** (minimum 600,000 iterations), **Argon2id** (memory-hard, preferred), or **scrypt**.

### 3.3 End-to-End Encryption (Signal Protocol)

**Double Ratchet algorithm components:**
| Component | Purpose | Algorithm |
|---|---|---|
| X3DH | Initial key agreement | X25519 |
| Double Ratchet | Ongoing key management | X25519 + HKDF + AES-GCM |
| Sending Chain | Per-message encryption keys | HMAC-SHA256 chain |
| Root Chain | Derives new chain keys on DH ratchet | HKDF |

**Forward secrecy**: Each message uses unique key. After use, key is deleted. Compromise of current state does not reveal past messages.

### 3.4 Zero-Knowledge Proofs for Authentication

**Schnorr Protocol (Interactive ZKP):**
1. **Setup**: Public generator g, prime p, q (order of g)
2. **Registration**: Prover computes y = g^x mod p
3. **Commitment**: Prover sends t = g^r mod p (random r)
4. **Challenge**: Verifier sends random c
5. **Response**: Prover sends s = r + c*x mod q
6. **Verify**: Check g^s == t * y^c mod p

**Three properties**: Completeness (honest prover convinces), Soundness (dishonest prover cannot), Zero-Knowledge (verifier learns nothing).

---

## 4. JWT Algorithm Confusion

### 4.1 Attack Classes

| Attack | Description | Severity |
|---|---|---|
| **Algorithm Confusion** | Switch RS256 → HS256, sign with public key as HMAC secret | **Critical** |
| **None Algorithm** | Set alg=none to bypass signature verification entirely | **Critical** |
| **KID Injection** | SQLi, path traversal, or SSRF via kid header parameter | **High** |
| **JKU/X5U Injection** | Point key source URL to attacker-controlled server | **High** |
| **Weak Secret** | Brute-force short HMAC secrets | **Critical** |
| **Token Replay** | Reuse valid tokens without proper expiration/revocation | **High** |

### 4.2 Algorithm Confusion Attack (RS256 → HS256)

**Mechanism**: Server's JWT verification library trusts the `alg` header. Attacker changes from RS256 to HS256, signs with the RSA public key (available from JWKS endpoint) as the HMAC secret. Server uses same public key to verify → signature succeeds.

**Attack steps:**
1. Obtain valid JWT through legitimate authentication
2. Extract RSA public key from JWKS endpoint (`/.well-known/jwks.json`)
3. Create new JWT with `{"alg":"HS256","typ":"JWT"}` header
4. Sign with HMAC-SHA256 using RSA public key PEM bytes as secret
5. Server verifies with same public key → authentication bypass

**Key formats to try**: Full PEM, PEM without headers, no newlines, DER, raw Base64-only.

### 4.3 None Algorithm Attack

**Variations to test:**
- `"alg": "none"`, `"alg": "None"`, `"alg": "NONE"`, `"alg": "nOnE"`
- Missing alg entirely
- Different signature options: empty, dot, original signature, null byte

### 4.4 KID Header Injection

**Injection vectors:**
- `../../../../../../dev/null` → Sign with empty key
- `' UNION SELECT 'secret-key' FROM dual--` → SQL injection in key lookup
- `' OR '1'='1` → SQL injection
- `https://attacker.com/key.pem` → URL-based key retrieval

### 4.5 JKU Injection

**Mechanism**: Modify JWT header's `jku` (JWK Set URL) to point to attacker-hosted JWKS endpoint. Server fetches keys from attacker's URL, verifies attacker-signed tokens as valid.

**URL bypass techniques:**
- `https://target.com@attacker.com/jwks`
- `https://target.com/.well-known/jwks.json#@attacker.com`

### 4.6 Defensive Measures

- **Enforce algorithm allowlist** in verification: `jwt.verify(token, key, algorithms=["RS256"])`
- **Never accept alg=none** in production
- Use asymmetric algorithms (RS256, ES256, EdDSA) for distributed systems
- Set short expiration (15 min for access tokens)
- Implement **token refresh mechanism**
- Store secrets securely (not in source code)
- Validate `kid` parameter against strict allowlist
- Ignore or validate `jku`/`x5u` headers against known endpoints

### 4.7 JWT Vulnerability Testing Tools

| Tool | Purpose |
|---|---|
| **jwt_tool** | Python JWT testing with 12+ attack modes |
| **Burp JWT Editor** | Decode, edit, re-sign JWTs with algorithm manipulation |
| **hashcat (mode 16500)** | GPU-accelerated HMAC secret brute-forcing |
| **John the Ripper** | CPU-based JWT secret cracking |
| **jwt.io** | Online JWT decoder and debugger |

---

## 5. API Security Testing Methodology

### 5.1 OWASP API Security Top 10 Testing Framework

**Key vulnerability categories:**

| # | Vulnerability | Description |
|---|---|---|
| API1 | **BOLA** (Broken Object Level Authorization) | IDOR — access other users' objects by changing identifiers |
| API2 | **Broken Authentication** | Weak token validation, missing auth on endpoints |
| API3 | **Broken Object Property Level Authorization** | Excessive data exposure, mass assignment |
| API5 | **BFLA** (Broken Function Level Authorization) | Low-privilege access to admin functions |
| API8 | **Security Misconfiguration** | Verbose errors, debug endpoints exposed |
| API9 | **Improper Inventory Management** | Shadow/zombie APIs, undocumented endpoints |

### 5.2 Testing Workflow

**Step 1 — API Discovery:**
- Import OpenAPI/Swagger specs into Postman/Burp Suite
- Reverse-engineer undocumented APIs via mobile app proxy capture
- GraphQL introspection: `{"query": "{__schema{types{name,fields{name}}}}"}`
- Fuzz for hidden versions (`/api/v1/`, `/api/v2/`, `/api/internal/`)

**Step 2 — Authentication Testing:**
- JWT analysis: algorithm, expiration, claims
- OAuth 2.0: redirect_uri manipulation, authorization code reuse
- API key validation per-endpoint, revoked key behavior

**Step 3 — Authorization Testing (BOLA/BFLA):**
- Replace object identifiers: `GET /api/users/123/orders` → `GET /api/users/456/orders`
- Test with numeric IDs, UUIDs, usernames, email addresses
- BFLA: Use low-privilege token to access admin endpoints
- HTTP method testing: GET → PUT → PATCH → DELETE on same endpoints

**Step 4 — Input Validation:**
- SQL injection in JSON body parameters
- NoSQL injection: `{"username": {"$gt": ""}, "password": {"$gt": ""}}`
- SSRF via webhook/avatar URLs
- Rate limiting validation at auth endpoints

**Step 5 — Data Exposure:**
- Compare UI displayed fields vs API response fields
- Trigger error responses for stack traces
- Test paginated enumeration
- Check debug endpoints: `/api/debug`, `/metrics`, `/.env`

### 5.3 API Authentication Weakness Testing

**Authentication mechanism identification:**
1. Probe unauthenticated access on all endpoints
2. Check WWW-Authenticate header for scheme (Bearer, Basic)
3. Login and examine tokens (JWT structure, refresh tokens, cookies)

**JWT analysis checks:**
- Algorithm: if `alg=none` → critical
- Symmetric algorithm: check for weak/default secrets
- Expiration: no `exp` claim → never expires
- Sensitive data in payload
- Missing standard claims (iss, aud, iat, sub)

**Token lifecycle testing:**
- Token reuse after logout (should be server-side revoked)
- Refresh token rotation enforcement
- Token acceptance in query parameters (leakage risk)

**Password policy testing:**
- Weak password acceptance (too short, common, no complexity)
- Account enumeration via different error messages

### 5.4 API Fuzzing with RESTler

**RESTler modes:**
| Mode | Purpose |
|---|---|
| **test** | Quick validation that all endpoints reachable |
| **fuzz-lean** | One pass with security checkers (UseAfterFree, NamespaceRule, LeakageRule, etc.) |
| **fuzz** | Extended fuzzing for comprehensive coverage |

**RESTler checkers:**
- **UseAfterFree**: Accessing resources after deletion
- **NamespaceRule**: Cross-tenant data access
- **ResourceHierarchy**: Wrong parent IDs for child resources
- **LeakageRule**: Information disclosure in errors
- **PayloadBody**: Fuzzing request body fields

### 5.5 Shadow API Detection

**Detection methods:**
1. **Traffic analysis**: Compare observed traffic against documented OpenAPI specs
2. **Cloud configuration scanning**: AWS API Gateway, Lambda function URLs, ALB rules
3. **Source code mining**: Grep for route definitions in Express, Flask, Spring Boot
4. **JavaScript analysis**: Extract API endpoints from frontend JS bundles

**Shadow API risk classification** (scoring):
- No authentication: +3
- High traffic volume: +2
- Multiple source IPs: +2
- Write operations: +2
- Sensitive path patterns (admin, debug, internal): +3

---

## 6. Rate Limiting and Schema Validation

### 6.1 Rate Limiting Algorithms

| Algorithm | Mechanism | Burst Handling | Complexity |
|---|---|---|---|
| **Sliding Window** | Rolling window via Redis sorted sets | Smooth | Medium |
| **Token Bucket** | Tokens added at fixed rate, consumed per request | Controlled bursts | Medium |
| **Fixed Window** | Count per fixed time period | Burst at boundaries | Low |

**Rate limit response headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1609459200
Retry-After: 30
```

**Tiered rate limiting example:**
| Tier | Default | Search | Export | Auth (per IP) |
|---|---|---|---|---|
| Free | 60/min | 10/min | 5/hour | 5/min |
| Premium | 300/min | 50/min | 20/hour | 5/min |
| Enterprise | 1000/min | 200/min | 100/hour | 10/min |

**Critical implementation details:**
- Use **Redis** for distributed rate limit state across multiple instances
- Implement rate limiting on **authentication endpoints separately** from general API limits
- Never trust X-Forwarded-For without validation against load balancer
- **429 responses** must include Retry-After header
- Return structured JSON error: `{"error": "rate_limit_exceeded", "retry_after": 30}`

### 6.2 API Schema Validation

**Key OpenAPI security constraints:**
- `additionalProperties: false` — **prevents mass assignment**
- `maxLength` on all string fields — prevents buffer overflow/DoS
- `pattern` on string fields — regex restricts input character set
- `enum` for fixed-value fields — prevents unexpected input
- `readOnly` fields enforced server-side — prevents data manipulation
- Define all 4xx/5xx response schemas — prevents information leakage

**Schema validation middleware (FastAPI example):**
```python
class ProductCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')  # CRITICAL: mass assignment prevention
    name: str = Field(min_length=1, max_length=200, pattern=r'^[a-zA-Z0-9\s\-\.]+$')
    price: float = Field(gt=0, le=999999.99)
    category: str = Field(pattern=r'^(electronics|clothing|food|furniture|other)$')
```

**Security anti-patterns:**
| Anti-Pattern | Risk | Fix |
|---|---|---|
| `additionalProperties: true` or missing | Mass assignment | Set `additionalProperties: false` |
| No `maxLength` on strings | Buffer overflow, DoS | Add maxLength constraints |
| No `pattern` on fields | Injection attacks | Add regex patterns |
| No `enum` for fixed values | Unexpected processing | Use enum |
| Missing error response schemas | Information leakage | Define all error schemas |

---

## 7. Firewall and IDS Configuration

### 7.1 pfSense Firewall Rules

**Zone-based architecture:**
| Zone | VLAN | Trust Level | Access Policy |
|---|---|---|---|
| WAN | — | None | Default deny inbound |
| LAN (Corporate) | 10 | Medium | Controlled access to internal resources |
| DMZ | 10 | Low | Limited inbound, restricted outbound |
| Guest | 30 | Low | Internet only, no internal access |
| IoT | 40 | Low | Cloud endpoints only, no inter-device |
| Servers | 20 | High | Strict ACLs |

**Rule processing**: Rules evaluate top-to-bottom within each interface tab. First match wins. Unmatched traffic blocked by default.

**pfBlockerNG**: IP reputation blocklists (Spamhaus DROP, Emerging Threats) + DNSBL for malware domain blocking.

### 7.2 Palo Alto Next-Generation Firewall

**Four pillars of Palo Alto security:**
1. **App-ID**: Traffic classification by application regardless of port/protocol/encryption
2. **User-ID**: Maps IP addresses to user identities (AD Event Logs, RADIUS, GlobalProtect)
3. **Content-ID**: Threat inspection (AV, AS, VP, URL Filtering, File Blocking, WildFire)
4. **SSL Decryption**: Forward Proxy for outbound, Inbound Inspection for servers

**Zone Protection Profiles**: SYN flood protection with configurable alert-rate, activate-rate, maximal-rate, and SYN cookies.

**Security policy best practices:**
- Start with **deny-all** and explicitly allow only required applications
- Replace port-based rules with **App-ID rules** using Policy Optimizer
- Decrypt at least **80% of SSL traffic** with privacy exclusions
- Apply security profiles as a group (AV + AS + VP + URL + FB + WF)
- Enable **automatic daily content updates**

### 7.3 Snort 3 IDS

**Configuration (Lua-based):**
```
HOME_NET = '10.10.0.0/16'
EXTERNAL_NET = '!$HOME_NET'
```

**Custom rule examples:**
```
# Reverse shell detection
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (
    msg:"LOCAL Possible Reverse Shell on port 4444";
    flow:established,to_server; content:"/bin/sh"; nocase;
    sid:1000001; rev:1; classtype:trojan-activity; priority:1;
)

# DNS tunneling (high-entropy long subdomain)
alert udp $HOME_NET any -> any 53 (
    msg:"LOCAL Possible DNS Tunneling - Long Query Name";
    content:"|01 00|"; offset:2; depth:2;
    byte_test:1,>,50,12;
    sid:1000003; rev:1; classtype:policy-violation; priority:2;
)
```

**Tuning mechanisms:**
- **Threshold**: Control alert frequency (`threshold:type both, track by_src, count 100, seconds 10`)
- **Suppress**: Silence alerts from specific sources/destinations
- **PulledPork 3**: Automated rule management

### 7.4 Suricata IDS/IPS

**Advantages over Snort**: Multi-threaded packet processing (10+ Gbps), protocol-aware inspection, **JA3/HASSH fingerprinting**, EVE JSON structured logging, Community ID for cross-tool correlation.

**AF_PACKET configuration for high performance:**
```yaml
af-packet:
  - interface: eth1
    threads: auto
    cluster-type: cluster_flow
    ring-size: 200000
    buffer-size: 262144
```

**EVE JSON logging types**: alert, http, dns, tls, files, smtp, flow, netflow, anomaly, stats

**Custom rule for Cobalt Strike detection:**
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"LOCAL Cobalt Strike JA3 Hash";
    ja3.hash; content:"72a589da586844d7f0818ce684948eea";
    sid:9000003; rev:1; classtype:trojan-activity; priority:1;
)
```

### 7.5 Network Segmentation with Firewall Zones

**Segmentation approaches:**
| Approach | Scope | Granularity | Use Case |
|---|---|---|---|
| VLAN | Layer 2 | Subnet-level | Department separation |
| Firewall Zones | Layer 3-7 | Zone-to-zone | Inter-zone policy |
| ACLs on Routers | Layer 3-4 | Subnet/port | Quick filtering |
| Microsegmentation | Layer 3-7 | Workload-level | Zero trust, containers |
| SGT/TrustSec | Layer 2-7 | Tag-based | Identity-based segmentation |

**Zone tiers:**
| Zone | Trust Level | Access Policy |
|---|---|---|
| Internet | None | Default deny inbound |
| DMZ | Low | Limited inbound, restricted outbound |
| Guest | Low | Internet only, no internal access |
| Corporate | Medium | Controlled access to internal resources |
| Server/Data Center | High | Strict ACLs, limited admin access |
| PCI CDE | Critical | PCI DSS compliant isolation |
| Management | Critical | Jump box only |

**Validation**: Test connectivity between zones, verify both allowed and blocked paths. Automate with scripts that test TCP/UDP/ICMP across zone boundaries.

### 7.6 Network Access Control (802.1X)

**Components:**
- **FreeRADIUS**: EAP-PEAP/EAP-TLS, LDAP integration, dynamic VLAN assignment
- **PacketFence**: Posture assessment, captive portal, device registration
- **Managed switches**: 802.1X port-based authentication, MAB fallback

**Dynamic VLAN assignment by group:**
```
IT-Staff → VLAN 10
Developers → VLAN 15
Finance → VLAN 20
Unknown/Guest → VLAN 40
Quarantine (posture fail) → VLAN 999
```

**Critical failover**: Configure critical VLAN for RADIUS server unavailability to prevent network lockout.

---

## 8. Zero Trust Implementation

### 8.1 Zero Trust Network Access (ZTNA)

**Core principle**: Never trust, always verify. Every access request authenticated regardless of network location.

**Implementation components:**
| Component | Purpose | Examples |
|---|---|---|
| Identity Provider | User authentication + MFA | Entra ID, Okta, Google Workspace |
| Access Proxy | Identity-aware access | AWS Verified Access, GCP IAP, Cloudflare Access |
| Device Management | Posture assessment | Intune, Jamf, CrowdStrike |
| Microsegmentation | Workload isolation | Security groups, K8s NetworkPolicy |
| Continuous Verification | Ongoing trust assessment | Re-authentication every 4 hours |

**Cloud-native ZTNA implementations:**
- **GCP IAP**: Identity-Aware Proxy for web apps and VMs
- **AWS Verified Access**: OIDC trust providers + access groups with IAM policies
- **Azure Conditional Access**: Policy engine based on user, device, location, risk

**Micro-segmentation (Kubernetes example):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
spec:
  podSelector:
    matchLabels:
      app: api-server
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web-frontend
      ports:
        - protocol: TCP
          port: 8080
```

### 8.2 Tailscale Zero Trust VPN

**Architecture**: WireGuard-based mesh VPN with end-to-end encryption using Curve25519 key exchange. Peer-to-peer connections with DERP relay as fallback.

**ACL policy (JSON):**
```json
{
  "acls": [
    {"action": "accept", "src": ["group:engineering"], "dst": ["tag:dev-server:*"]},
    {"action": "accept", "src": ["group:sre"], "dst": ["tag:production:22,443,8080"]}
  ],
  "ssh": [
    {"action": "check", "src": ["group:sre"], "dst": ["tag:production"], "users": ["root","admin"]}
  ]
}
```

**Key features:**
- Default deny-all ACL policy (zero trust by design)
- **Tailscale SSH**: Identity-based SSH without key management
- **Tailnet Lock**: Prevents unauthorized nodes from joining
- **MagicDNS**: Hostname-based resolution across tailnet
- **Self-hosted option**: Headscale (open-source control server)

---

## 9. DDoS Mitigation

### 9.1 DDoS Attack Categories

| Layer | Attack Type | Examples | Mitigation |
|---|---|---|---|
| L3/4 | Volumetric | SYN flood, UDP flood, DNS amplification | Network-layer DDoS managed rules |
| L3/4 | Protocol | Ping of Death, Smurf, IP fragmentation | Advanced TCP Protection |
| L7 | Application | HTTP flood, Slowloris, cache busting | HTTP DDoS rules, WAF, Rate Limiting |
| DNS | DNS-specific | DNS query flood, NXDOMAIN | Advanced DNS Protection |

### 9.2 Cloudflare DDoS Protection Stack

**Processing order at Cloudflare edge:**
```
L3/4 DDoS Managed Rules → IP Access Rules → Bot Management → WAF Managed Rules → Rate Limiting → HTTP DDoS Rules → Origin
```

**Rate limiting rules (Cloudflare):**
```json
{
  "ratelimit": {
    "characteristics": ["cf.colo.id", "ip.src"],
    "period": 60,
    "requests_per_period": 10,
    "mitigation_timeout": 600
  }
}
```

**WAF custom rules:**
- Block known bad ASNs
- Challenge requests without User-Agent
- Block high-risk countries for admin paths
- Block oversized request bodies

### 9.3 Origin Protection

**Critical**: Origin server must only accept traffic from Cloudflare:
```bash
# Allow only Cloudflare IPs
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    iptables -A INPUT -p tcp --dport 443 -s $ip -j ACCEPT
done
iptables -A INPUT -p tcp --dport 443 -j DROP
```

**Authenticated Origin Pulls**: Mutual TLS ensuring only Cloudflare can reach origin.

### 9.4 Auto-Response Script

```python
# Monitor traffic and auto-enable "Under Attack" mode
NORMAL_RPS_THRESHOLD = 5000
# If RPS > threshold → set_security_level("under_attack")
# If traffic normalizes for 5 consecutive checks → restore "high"
```

---

## 10. WAF Deployment and Tuning

### 10.1 Cloud WAF (AWS WAF / Azure WAF / Cloudflare)

**Deployment strategy:**
1. Start with **managed rule sets** in **Count mode** (detection only)
2. Enable: AWSManagedRulesCommonRuleSet, SQLiRuleSet, KnownBadInputsRuleSet
3. Create **rate-based rules** for auth endpoints (100 req/5min/IP)
4. Configure **geo-blocking** for countries without legitimate users
5. Analyze WAF logs (Athena/Splunk) for false positives
6. Create **rule exclusions** for legitimate traffic patterns
7. After 7-14 days, switch to **Block mode**

**Key concepts:**
| Term | Definition |
|---|---|
| Web ACL | Rule set evaluated against every HTTP request |
| Managed Rule Group | Pre-configured rules by vendor (OWASP, AWS, Cloudflare) |
| Rate-Based Rule | Tracks request rates per IP, blocks exceeding threshold |
| Scope-Down Statement | Narrows rate rule to specific URI paths/methods |
| Count Mode | Logs matching requests without blocking (validation phase) |

**False positive management:**
- Query WAF logs to find most-triggered rules for legitimate traffic
- Create exclusions for specific URI paths (e.g., file upload endpoints)
- Document all exclusions for audit trail

### 10.2 ModSecurity WAF with OWASP CRS

**Deployment steps:**
1. Install ModSecurity v3 with Apache/Nginx
2. Deploy **OWASP CRS v4** with paranoia level (PL1-PL4)
3. Configure **SecRuleEngine** in `DetectionOnly` mode
4. Configure **SecAuditEngine** for relevant-only logging
5. Tune false positives with `SecRuleRemoveById` and rule exclusions
6. Switch to blocking mode after tuning period
7. Forward audit logs to SIEM

**CRS Paranoia Levels:**
| Level | Description | False Positive Risk |
|---|---|---|
| PL1 | Basic attacks, minimal FP | Low |
| PL2 | More advanced attacks | Medium |
| PL3 | Aggressive detection | High |
| PL4 | Maximum security | Very High |

**ModSecurity audit log format:**
```
ModSecurity: Warning. Pattern match "(?:union\s+select)"
[file "/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]
[line "45"] [id "942100"]
[msg "SQL Injection Attack Detected via libinjection"]
[severity "CRITICAL"]
```

---

## Cross-Cutting Themes

### Defense in Depth

The skills consistently emphasize **layered defense**:
- TLS encryption + WAF inspection + application validation
- Network segmentation + firewall zones + host-based firewalls
- Rate limiting at multiple layers (cloud WAF + API gateway + application)
- Authentication at identity layer (ZTNA) + network layer (802.1X) + application layer (JWT)

### Shift-Left Security

- Schema validation in CI/CD catches mass assignment and injection before deployment
- RESTler fuzzing in staging catches stateful bugs before production
- API schema compliance testing prevents response schema drift

### Observability as Control

- Structured logging (EVE JSON, WAF logs, firewall logs) enables detection
- Rate limit metrics inform traffic baselines
- JA3/HASSH fingerprinting enables threat hunting
- Community ID enables cross-tool correlation

### Key Takeaways

1. **JWT security is fragile**: Always enforce algorithm allowlists, never trust `alg` header
2. **API attack surface is underestimated**: Shadow APIs and undocumented endpoints are common
3. **Encryption without inspection is insufficient**: TLS inspection closes the visibility gap
4. **Zero trust replaces perimeter thinking**: Every connection verified, every access authorized
5. **WAF is a compensating control**: It protects against exploitation, not root causes
6. **Rate limiting must be distributed**: In-memory rate limiting bypasses with multiple servers
7. **Schema validation prevents mass assignment**: `additionalProperties: false` is critical
8. **Post-quantum readiness is approaching**: Start inventorying cryptographic dependencies

---

*Synthesized from 33 Anthropic Cybersecurity Skills. Key skills not found: `implementing-nginx-security-hardening`, `implementing-post-quantum-cryptography-migration`.*
