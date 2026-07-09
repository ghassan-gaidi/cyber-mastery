# Identity Security, Zero Trust Architecture & Access Governance Mastery

> Comprehensive synthesis from 31 cybersecurity skills covering identity verification, zero trust implementation, privileged access management, identity governance, and network segmentation.

---

## 1. Zero Trust Maturity Model (CISA ZTMM v2.0)

### Framework Overview

The CISA Zero Trust Maturity Model defines **five pillars** and **three cross-cutting capabilities**, each progressing through four maturity stages: **Traditional → Initial → Advanced → Optimal**.

### The Five Pillars

| Pillar | Traditional | Initial | Advanced | Optimal |
|--------|------------|---------|----------|---------|
| **Identity** | Password-based auth, manual provisioning | MFA for privileged users, basic lifecycle | Phishing-resistant MFA (FIDO2), continuous validation, ITDR | Real-time identity verification, AI-driven anomaly detection, passwordless across all systems |
| **Devices** | Limited inventory, basic AV | Comprehensive inventory, EDR, basic health checks | Real-time posture assessment, device certificates, vulnerability scanning | Continuous trust scoring, automated remediation, firmware integrity verification |
| **Networks** | Perimeter-based (firewalls, VPNs), flat internal | Initial segmentation, encrypted DNS | Microsegmentation, SDN, NDR, full TLS internal encryption | Fully software-defined, zero implicit trust zones, AI-driven anomaly detection |
| **Applications** | Perimeter-protected, manual patching | App-level access controls, WAF, regular scanning | SAST/DAST integration, API security gateways, immutable infrastructure | RASP, automated security orchestration, zero-standing privileges |
| **Data** | Basic encryption at rest, limited classification | Data classification, DLP, TLS 1.2+, basic inventory | Automated classification, fine-grained access, rights management | Real-time flow analytics, AI-driven classification, automated exfiltration response |

### Cross-Cutting Capabilities

1. **Visibility & Analytics**: Manual log review → Centralized SIEM → UEBA + data lake analytics → AI/ML predictive analytics
2. **Automation & Orchestration**: Manual IR → Basic SOAR playbooks → Multi-pillar orchestration → Fully autonomous self-healing
3. **Governance**: Ad-hoc policies → Documented strategy → Policy-as-code → Dynamic real-time governance engine

### Implementation Roadmap

```
Phase 1: Assessment     → Inventory all assets, map to maturity stages
Phase 2: Identity       → Deploy FIDO2, implement IGA, continuous verification
Phase 3: Device Trust   → Complete inventory, deploy EDR, device certificates
Phase 4: Network        → Segment networks, deploy microsegmentation, NDR
Phase 5: Applications   → App-level controls, WAF, DevSecOps pipeline
Phase 6: Data           → Classification, DLP, rights management, lifecycle governance
```

### Key NIST References
- **NIST SP 800-207**: Zero Trust Architecture principles
- **OMB M-22-09**: Federal zero trust mandates
- **NIST SP 800-63B**: Digital identity guidelines
- **CISA ZTMM v2.0**: Progressive maturity roadmap

---

## 2. Identity Verification Methods

### Continuous Identity Verification Architecture

Zero trust requires identity verification that goes beyond one-time authentication:

```
User Request → Primary Auth (FIDO2/Cert) → Contextual Assessment → Risk Scoring → Access Decision
                                                              ↓
                                                    Low Risk → Grant Access
                                                    High Risk → Step-up Auth (hardware key, biometric, manager approval)
```

### Verification Signals

| Signal Category | Examples | Weight |
|----------------|----------|--------|
| **Identity** | Username/password, FIDO2, certificate, biometric | Primary |
| **Device Posture** | OS version, encryption, EDR status, patch level | High |
| **Network Context** | IP reputation, geolocation, VPN status | Medium |
| **Behavioral** | Login time patterns, access frequency, geo-velocity | Medium |
| **Risk Signals** | Impossible travel, credential stuffing, token replay | Dynamic |

### Identity Threat Detection & Response (ITDR)

- **Impossible travel detection**: Flag logins from geographically impossible locations
- **Anomalous token patterns**: Detect token theft/replay attacks
- **Credential stuffing detection**: Identify brute-force and credential spray patterns
- **Session anomaly**: Monitor for session hijacking indicators

### Microsoft Entra ID Protection Risk Levels

| Risk Level | Action | Response |
|-----------|--------|----------|
| Low | Allow | Grant access with standard MFA |
| Medium | Require MFA | Step-up authentication required |
| High | Block + Investigate | Block access, alert SOC, require admin reset |

### Continuous Access Evaluation (CAE)

- Real-time token revocation on critical events (user disabled, password changed, location change)
- Token revocation within **minutes** instead of hours
- Critical event triggers: user compromise, device non-compliance, policy changes

---

## 3. SSO/SAML/OIDC Implementation

### SAML 2.0 Authentication Flows

**SP-Initiated Flow:**
```
User → SP (AuthnRequest) → IdP → User authenticates → IdP (SAML Response) → SP validates → Access granted
```

**IdP-Initiated Flow:**
```
User → IdP (authenticates) → Selects app → IdP (SAML Response) → SP validates → Access granted
```

### Critical SAML Security Requirements

| Control | Requirement |
|---------|------------|
| **Signatures** | SHA-256 mandatory (never SHA-1) |
| **Encryption** | AES-256-CBC for assertion attributes |
| **Audience Restriction** | Prevents assertion replay across SPs |
| **Time Validity** | NotBefore/NotOnOrAfter enforcement |
| **InResponseTo** | Verify assertion matches original AuthnRequest |

### Okta SAML Configuration Parameters

| Parameter | Value |
|-----------|-------|
| ACS URL | `https://www.google.com/a/{domain}/acs` |
| Entity ID | `google.com/a/{domain}` |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| Binding | HTTP-POST (ACS), HTTP-Redirect (SSO URL) |

### Google Workspace SSO Integration

- **ACS URL**: `https://www.google.com/a/{your-domain}/acs`
- **Entity ID**: `google.com/a/{your-domain}`
- SSO profiles assignable at org-wide, OU, or group level
- Network masks control when SSO is enforced based on IP
- **Break-glass accounts**: Always maintain Google-native admin accounts bypassing SSO

### SCIM 2.0 Provisioning

| Operation | HTTP Method | Endpoint | Description |
|-----------|-------------|----------|-------------|
| Create User | POST | /scim/v2/Users | Provisions new account |
| Read User | GET | /scim/v2/Users/{id} | Retrieves user details |
| Update User | PUT/PATCH | /scim/v2/Users/{id} | Modifies attributes |
| Delete User | DELETE | /scim/v2/Users/{id} | Removes account (soft delete) |
| List Users | GET | /scim/v2/Users | Lists with filtering |

**Key SCIM Requirements:**
- Bearer token authentication on all endpoints
- `userName eq "..."` filter support (required by Okta)
- Pagination: `startIndex`, `itemsPerPage`, `totalResults`
- User deactivation = `active: false` (not hard delete)

---

## 4. MFA and Passwordless Authentication

### FIDO2/WebAuthn Architecture

```
Registration:  Server.register_begin() → Browser.credentials.create() → Server.register_complete()
Authentication: Server.authenticate_begin() → Browser.credentials.get() → Server.authenticate_complete()
```

### Key FIDO2 Concepts

| Term | Definition |
|------|-----------|
| **FIDO2** | W3C WebAuthn + FIDO Alliance CTAP2 standard |
| **WebAuthn** | W3C API for `navigator.credentials.create()` and `.get()` |
| **CTAP2** | Client-to-Authenticator Protocol (USB/NFC/BLE) |
| **Discoverable Credential** | Passkey enabling username-less login |
| **Attestation** | Cryptographic proof of authenticator identity |
| **AAGUID** | 128-bit identifier for authenticator model |
| **Sign Count** | Monotonically increasing counter for clone detection |
| **User Verification** | Local auth (PIN, biometric) on the authenticator |

### Microsoft Entra Passwordless Methods

| Method | Deployment | Authentication Factor |
|--------|-----------|----------------------|
| **FIDO2 Security Keys** | Entra admin > Authentication methods | Hardware key with PIN/biometric |
| **Windows Hello for Business** | Intune MDM configuration profile | TPM-protected PIN/facial recognition |
| **Microsoft Authenticator Passkey** | Authenticator app 6.8+ | Device-level biometric/PIN |
| **Certificate-Based Auth** | X.509 certificate on device | Certificate + PIN |

### Authentication Strength (Conditional Access)

```powershell
# Create phishing-resistant authentication strength
$authStrength = @{
    displayName = "Phishing-Resistant Passwordless"
    allowedCombinations = @("fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor")
    requirementsSatisfied = "mfa"
}
```

### YubiKey Enrollment Best Practices

1. **Primary + backup keys**: Require 2 keys per user minimum
2. **PIN initialization**: Minimum 4 characters, 8 retries before lockout
3. **Attestation verification**: Confirm genuine YubiKey via AAGUID
4. **Sign count monitoring**: Detect cloned keys
5. **User verification required**: `user_verification: required` (not discouraged)

### Passwordless Migration Strategy

```
Phase 1 (Month 1-2):   Enable FIDO2 + WHfB in report-only Conditional Access
Phase 2 (Month 2-3):   Deploy WHfB via Intune with Cloud Kerberos Trust
Phase 3 (Month 3-5):   Distribute FIDO2 keys to highest-risk users first
Phase 4 (Month 5-8):   Enable Authenticator passkeys for mobile users
Phase 5 (Month 8-10):  Switch to enforced phishing-resistant auth
Phase 6 (Month 10-12): Disable SMS/voice, block legacy auth protocols
```

### Legacy MFA Deprecation

- **Disable SMS and voice call** authentication methods
- **Block legacy protocols** (basic auth, IMAP, POP3) via Conditional Access
- **Monitor adoption**: Track passkey vs. password login ratio
- **Temporary Access Pass (TAP)**: Time-limited codes for registration/recovery

---

## 5. Privileged Access Management (PAM)

### Privileged Account Categories

| Category | Examples | Risk Level | Review Frequency |
|----------|----------|------------|-----------------|
| Domain Admins | Enterprise Admin, Schema Admin | Critical | Monthly |
| Service Accounts | SQL service, backup agents | High | Quarterly |
| Cloud IAM | AWS root, Azure Global Admin | Critical | Monthly |
| Database Admin | DBA accounts, sa/sys | High | Quarterly |
| Application Admin | App admin roles, API keys | Medium | Semi-annually |
| Emergency/Break-glass | Firecall accounts | Critical | After each use |

### PSM (Privileged Session Manager) Architecture

```
Admin User → PVWA (Web Portal) → PSM (Jump Server) → Target Server
                    │                    │                     │
            MFA + AD Auth    Credentials never    Session recorded
                            exposed to admin      and stored in Vault
```

**Network Controls:**
- DENY direct RDP (3389) and SSH (22) from user networks
- ALLOW RDP/SSH ONLY from PSM server IPs
- PSM server: Hardened, no internet, restricted local admin

### Session Recording Configuration

| Setting | Value |
|---------|-------|
| Record Sessions | Yes |
| Recording Format | AVI (video) + Keystrokes (text) |
| Retention (PCI-DSS) | 1 year, available 3 months |
| Retention (SOX) | 7 years |
| Retention (HIPAA) | 6 years |
| Compression | Medium |

### Privileged Threat Analytics (PTA) Rules

| Rule | Trigger | Action |
|------|---------|--------|
| High-Risk Command | `rm -rf`, `chmod 777`, `iptables -F` | Alert SOC + Flag session |
| Credential Access | mimikatz, procdump targeting lsass | Terminate + Alert + Lock |
| Unusual Duration | Session > 4 hours | Alert SOC for review |

### HashiCorp Boundary for Zero Trust Access

- **Default-deny model**: Users start with no access
- **Dynamic credential brokering**: Vault integration for ephemeral credentials
- **Session recording**: SSH/RDP sessions stored in S3
- **Just-in-time access**: Automatic credential revocation when sessions end

```
Boundary Architecture:
  Identity Provider (OIDC) → Boundary Controller → Boundary Worker → Target Hosts
                                        ↓
                               Vault (Credential Brokering)
                             - Dynamic database credentials
                             - SSH certificate signing
                             - Credential libraries
```

### Privileged Account Access Review Framework

```
DISCOVER → VALIDATE → REMEDIATE → MONITOR
    │           │           │          │
    ├─ Enumerate    ├─ Verify       ├─ Remove excess  ├─ Continuous
    │  all priv     │  justification│  privileges     │  monitoring
    │  accounts     ├─ Confirm      ├─ Disable        ├─ Anomaly
    ├─ Identify     │  ownership    │  orphaned        │  detection
    │  orphaned     ├─ Check        │  accounts        ├─ Session
    │  accounts     │  compliance   ├─ Enforce         │  recording
    └─ Classify     └─ Review       │  password        └─ Audit
       by risk        last usage    │  rotation           logging
                                    └─ Implement
                                       JIT access
```

---

## 6. Identity Governance and Lifecycle (IGA)

### Identity Lifecycle States

| State | Automated Actions | Valid Transitions |
|-------|------------------|-------------------|
| **PRE_HIRE** | Create identity, generate employee ID, mailbox reservation, birthright roles | ACTIVE, CANCELLED |
| **ACTIVE** | Create AD account, email, provision birthright apps, issue MFA token | ROLE_CHANGE, LEAVE_OF_ABSENCE, TERMINATED |
| **ROLE_CHANGE** | Recalculate roles, remove old dept access, provision new dept access | ACTIVE, LEAVE_OF_ABSENCE, TERMINATED |
| **LEAVE_OF_ABSENCE** | Disable login, suspend VPN, delegate mailbox, preserve roles | ACTIVE, TERMINATED |
| **TERMINATED** | Disable AD, revoke all access, convert mailbox, wipe mobile, archive | REHIRE, DELETED |
| **REHIRE** | Reactivate identity, reset credentials, re-enroll MFA | ACTIVE |
| **DELETED** | Delete AD account, delete email archive, remove IGA record | None |

### Authoritative Source Integration (Workday → IGA)

```python
# Lifecycle event mapping from Workday
if status == "Active" and hire_date > now:
    event = "PRE_HIRE"
elif status == "Active":
    event = "JOINER" or "MOVER"
elif status == "Terminated":
    event = "LEAVER"
elif status == "On Leave":
    event = "LEAVE_OF_ABSENCE"
```

### Role Mining Approaches

| Approach | Description | Best For |
|----------|-------------|----------|
| **Bottom-Up** | Analyze existing permissions for common patterns | Large datasets with organic growth |
| **Top-Down** | Design roles from business requirements | Greenfield RBAC |
| **Hybrid** | Combine bottom-up analysis with top-down validation | Most production environments |

### Role Mining Metrics

| Metric | Formula | Target |
|--------|---------|--------|
| Role Count | Total distinct roles | Minimize |
| Coverage | Permissions explained / Total | > 95% |
| Weighted Structural Complexity | Sum of role-user + role-permission | Minimize |
| Deviation | Extra permissions not in roles | < 5% |

### Birthright Access

- Entitlements automatically assigned based on job code
- If 80%+ of users with same job code have an entitlement → birthright
- Reduces access request volume by 25-40%

### Orphaned Account Detection

```python
active_employees = set(hr.get_active_employee_ids())
for app_account in app_connector.get_all_accounts():
    if correlated_id not in active_employees:
        # CRITICAL: privileged accounts → DISABLE_IMMEDIATELY
        # HIGH: active accounts → DISABLE_WITHIN_24H
        # MEDIUM: inactive accounts → REVIEW_AND_DISABLE
```

### Access Request Risk-Based Workflow

| Risk Level | Examples | Approval Chain | SLA |
|-----------|----------|----------------|-----|
| LOW | Email groups, SharePoint sites | Manager | 4 hours |
| MEDIUM | CRM admin, financial reporting | Manager + App Owner | 24 hours |
| HIGH | Database admin, cloud admin | Manager + App Owner + Security | 48 hours |
| CRITICAL | Domain Admin, AWS root | Manager + App Owner + Security + CISO | 72 hours |

---

## 7. Microsegmentation

### Microsegmentation Models

| Model | Tools | Enforcement Point |
|-------|-------|-------------------|
| **Network-Based** | VMware NSX, Cisco ACI | Hypervisor/network fabric |
| **Host-Based** | Illumio, Guardicore | OS iptables/WFP rules |
| **Container-Based** | Calico, Cilium | Pod/container level |
| **Application-Based** | Zscaler WKS | Software identity |

### Implementation Workflow

```
Phase 1: Discovery    → Deploy agents, map dependencies (2-4 weeks)
Phase 2: Policy Design → Define zones, create allow-lists, model in test mode
Phase 3: Enforcement   → Incremental enforcement with monitoring
Phase 4: Maintenance   → CI/CD integration, weekly violation review
```

### Application Dependency Mapping (Guardicore Reveal)

```bash
# Query discovered application flows
curl -s "https://management.guardicore.com/api/v3.0/connections" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{
    "time_range": {"from": "2026-02-17T00:00:00Z", "to": "2026-02-24T00:00:00Z"},
    "filter": {"source_label": "web-tier", "destination_label": "app-tier"},
    "aggregation": "process"
  }'
```

### Policy Types

| Policy | Action | Use Case |
|--------|--------|----------|
| **Allow** | Permit specific communication | Web → App on port 8080 |
| **Deny** | Block communication | Web → Database direct |
| **Ring-Fence** | Isolate entire zone | PCI CDE isolation |
| **Default Deny** | Block all unlisted | Zero trust baseline |

### Kubernetes NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-web-only
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web-frontend
      ports:
        - protocol: TCP
          port: 8080
```

### Best Practices

1. **Label-based policies** over IP-based (survives IP changes)
2. **Reveal mode first**: Test policies before enforcement
3. **Process-level granularity** where supported
4. **Ring-fence critical assets** (PCI, healthcare PHI)
5. **Integration with CI/CD**: Auto-label new workloads
6. **Break-glass procedures** documented and tested

---

## 8. Device Posture Assessment

### Device Compliance Baselines

**Windows (Intune):**
- BitLocker enabled, Secure Boot, TPM required
- Defender + firewall enabled
- OS >= 10.0.19045, password minimum 12 chars
- 24-hour grace period before blocking

**macOS (Jamf):**
- FileVault, Gatekeeper, SIP, Firewall enabled
- OS >= 14.0, screen lock <= 300 seconds
- Falcon sensor running

### CrowdStrike ZTA Score Thresholds

| Tier | ZTA Score | Access Level |
|------|-----------|-------------|
| Tier 1 | >= 50 | Basic access |
| Tier 2 | >= 65 | Standard access |
| Tier 3 | >= 80 | Sensitive access |
| Tier 4 | >= 90 | Critical access |

### Device Posture Signals Evaluated

| Signal | Source | Impact |
|--------|--------|--------|
| OS patch level | Intune/Jamf | Access tier selection |
| Disk encryption | BitLocker/FileVault | Required for access |
| EDR sensor status | CrowdStrike/Defender | Required for access |
| Firmware protection | Secure Boot/TPM | High-value target protection |
| Kernel protection | SIP/Code Integrity | Advanced protection |
| Firewall status | OS firewall | Baseline requirement |

### Cloudflare Device Posture Integration

```bash
# Add CrowdStrike device posture integration
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture/integration" \
  -d '{
    "name": "CrowdStrike Falcon",
    "type": "crowdstrike_s2s",
    "config": {
      "api_url": "https://api.crowdstrike.com",
      "client_id": "CS_CLIENT_ID",
      "client_secret": "CS_CLIENT_SECRET"
    },
    "interval": "10m"
  }'
```

### Okta Device Trust with CrowdStrike

```json
{
  "thirdPartySignalProviders": {
    "dtc": {
      "crowdStrikeCustomerId": "CS_CUSTOMER_ID",
      "crowdStrikeAgentId": "REQUIRED",
      "crowdStrikeVerifiedState": {"include": ["RUNNING"]}
    }
  }
}
```

### Continuous Posture Monitoring

- Monitor compliance drift in real-time
- Alert on: encryption disabled, EDR sensor stopped, OS downgraded
- Automated remediation via Intune: push BitLocker, deploy patches
- Weekly compliance reports for IT

---

## 9. Zero Trust Network Access (ZTNA) Implementations

### ZTNA Platform Comparison

| Platform | Architecture | Key Features |
|----------|-------------|--------------|
| **GCP IAP** | Identity-Aware Proxy | Access Context Manager, device trust |
| **AWS Verified Access** | Cloud-native ZTNA | OIDC trust providers, endpoint groups |
| **Azure Conditional Access** | Policy engine | Risk-based, device compliance |
| **Cloudflare Access** | Identity-aware proxy | Tunnel + WARP + device posture |
| **Zscaler ZPA** | App connectors | Outbound-only tunnels, Browser Access |
| **Palo Alto Prisma Access** | SASE | GlobalProtect, ZTNA Connectors, HIP |
| **Tailscale** | WireGuard mesh | ACL-based, identity-aware |
| **HashiCorp Boundary** | Identity-aware proxy | Vault integration, session recording |

### GCP Identity-Aware Proxy

```bash
# Enable IAP on App Engine
gcloud iap web enable --resource-type=app-engine

# Create Access Level requiring corporate device + MFA
gcloud access-context-manager levels create corporate-device \
  --basic-level-spec='{
    "conditions": [{
      "devicePolicy": {
        "requireScreenlock": true,
        "allowedEncryptionStatuses": ["ENCRYPTED"],
        "osConstraints": [
          {"osType": "DESKTOP_WINDOWS", "minimumVersion": "10.0.19041"}
        ]
      }
    }]
  }'
```

### AWS Verified Access

```bash
# Create Verified Access trust provider (OIDC)
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type oidc \
  --oidc-options '{
    "Issuer": "https://company.okta.com/oauth2/default",
    "ClientId": "CLIENT_ID",
    "ClientSecret": "CLIENT_SECRET",
    "Scope": "openid profile groups"
  }'
```

### Cloudflare Access + Tunnel

```bash
# Create tunnel to internal applications
cloudflared tunnel create internal-apps

# Configure ingress routes
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ingress:
  - hostname: wiki.company.com
    service: http://localhost:8080
  - hostname: git.company.com
    service: http://10.1.1.50:3000
  - service: http_status:404
EOF

# Route DNS to tunnel
cloudflared tunnel route dns internal-apps wiki.company.com
```

### Zscaler Private Access (ZPA)

```
Architecture:
  User → Zscaler Client Connector → ZPA Cloud → App Connector → Internal App
  
App Connector: Outbound-only (no inbound ports required)
Browser Access: Clientless option for web apps
Device Posture: CrowdStrike ZTA integration
```

### Tailscale Zero Trust VPN

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["tag:dev-server:*"]
    },
    {
      "action": "accept",
      "src": ["group:sre"],
      "dst": ["tag:production:22,443,8080"]
    }
  ],
  "ssh": [
    {
      "action": "check",
      "src": ["group:sre"],
      "dst": ["tag:production"],
      "users": ["root", "admin"]
    }
  ]
}
```

### Migration Strategy

1. **Inventory** all VPN-dependent applications
2. **Deploy** ZTNA proxy in front of each application
3. **Configure** OIDC integration with corporate IdP
4. **Implement** device trust policies
5. **Enable** continuous session evaluation
6. **Migrate** teams in phases (low-risk first)
7. **Decommission** VPN after 100% migration + 30-day parallel period

---

## 10. Just-in-Time (JIT) Access

### JIT Access Principles

- **No standing privileges**: Users request access only when needed
- **Time-limited**: Access automatically expires after defined duration
- **Approved access**: Risk-based approval chain before granting
- **Audited**: All sessions recorded and logged
- **Revoked**: Credentials destroyed when session ends

### HashiCorp Boundary + Vault JIT Flow

```
1. User authenticates to Boundary via OIDC
2. User selects target (SSH/RDP/Database)
3. Boundary requests credential from Vault
4. Vault generates dynamic credential (e.g., 30-minute DB password)
5. Boundary injects credential into session
6. Session is recorded
7. When session ends → credential automatically revoked by Vault
```

### JIT Access Configuration

```hcl
# Boundary target with time-limited access
resource "boundary_target" "ssh_production" {
  name         = "ssh-production-servers"
  session_max_seconds          = 3600  # 1 hour max
  session_connection_limit     = 1
  enable_session_recording     = true
  
  # Credential injected by Vault (user never sees it)
  injected_application_credential_source_ids = [
    boundary_credential_library_vault_ssh_certificate.ssh_cert.id
  ]
}
```

### Access Request with Time Limits

| Risk Level | Max Duration | Approval Required |
|-----------|-------------|-------------------|
| Low | 8 hours | Manager |
| Medium | 4 hours | Manager + App Owner |
| High | 2 hours | Manager + Security |
| Critical | 1 hour | CISO + Justification |

### JIT Access Benefits

1. **Reduced attack surface**: No standing privileges to steal
2. **Automatic credential rotation**: Fresh credentials per session
3. **Complete audit trail**: Every access session recorded
4. **Compliance**: Meets SOX, PCI-DSS, HIPAA requirements
5. **Incident response**: Instant access revocation when needed

---

## Summary: Key Implementation Patterns

### Pattern 1: Zero Trust for Cloud Applications
```
Identity Provider → Conditional Access → IAP/Verified Access → Application
       ↑                    ↑
  Device Posture      Risk Scoring
```

### Pattern 2: Passwordless Authentication
```
FIDO2 Key → WebAuthn API → Relying Party Server → Session
     ↓
  Sign Count (clone detection)
  User Verification (PIN/biometric)
```

### Pattern 3: Privileged Access Management
```
Admin → PSM (Jump Server) → Target
  ↓           ↓
MFA + AD    Session Recording
  ↓           ↓
PAM Vault   Audit Logs → SIEM
```

### Pattern 4: Identity Governance
```
HR System → IGA Platform → Application Provisioning
  ↓              ↓
Lifecycle      Access Reviews
Events         Role Mining
  ↓              ↓
Joiner/Mover   Certification
/Leaver        Campaigns
```

### Pattern 5: Microsegmentation
```
Workload → Agent → Policy Engine → Enforcement
  ↓            ↓           ↓
Labels     Visibility    Allow/Deny
           Mode          Rules
```

---

## Critical Success Factors

1. **Start with identity**: Identity is the foundation of zero trust
2. **Phishing-resistant MFA**: FIDO2/WebAuthn for all users
3. **Device trust**: Assess posture before granting access
4. **Least privilege**: Default deny, explicit allow
5. **Continuous verification**: Never trust, always verify
6. **Automate lifecycle**: JML automation reduces orphaned accounts
7. **Monitor everything**: SIEM integration for all access decisions
8. **Test before enforce**: Reveal/monitor mode before blocking
9. **Break-glass procedures**: Always maintain emergency access
10. **Measure progress**: Track maturity across all five pillars

---

*Generated from 31 cybersecurity skills covering zero trust architecture, identity security, PAM, IGA, microsegmentation, and access governance.*
