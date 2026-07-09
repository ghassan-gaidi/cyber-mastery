# Supply Chain Security & DevSecOps Mastery

> **Synthesized from 30 cybersecurity skills** covering SBOM, SAST/DAST/SCA, secrets scanning, container signing, supply chain integrity, IaC scanning, secrets management, PAM, and secure SDLC practices.
>
> **Generated**: 2026-07-09 | **Source Skills**: 30 Anthropic Cybersecurity Skills

---

## Table of Contents

1. [SBOM Generation and Analysis](#1-sbom-generation-and-analysis)
2. [SAST/DAST/SCA Integration](#2-sastdastsca-integration)
3. [Secrets Scanning in CI/CD](#3-secrets-scanning-in-cicd)
4. [Container Image Signing and Verification](#4-container-image-signing-and-verification)
5. [Supply Chain Integrity (in-toto, Cosign)](#5-supply-chain-integrity-in-toto-cosign)
6. [Infrastructure as Code Scanning](#6-infrastructure-as-code-scanning)
7. [Secrets Management (Vault, KMS)](#7-secrets-management-vault-kms)
8. [Privileged Access Management](#8-privileged-access-management)
9. [Secure SDLC Practices](#9-secure-sdlc-practices)
10. [Tool Matrix](#10-tool-matrix)
11. [Implementation Roadmap](#11-implementation-roadmap)
12. [Common Pitfalls](#12-common-pitfalls)

---

## 1. SBOM Generation and Analysis

### Core Concepts

An **SBOM (Software Bill of Materials)** is a machine-readable inventory of all components, libraries, and dependencies in a software product. Two primary standards exist:

| Standard | Maintainer | Strengths | Format |
|----------|-----------|-----------|--------|
| **CycloneDX** | OWASP | Dependency graphs, vulnerability data, BOM-specific | JSON, XML, Protobuf |
| **SPDX** | Linux Foundation | License compliance, file-level detail | JSON, RDF, Tag-Value |

### Generation Tools

- **Syft** (Anchore): Open-source, supports 30+ package ecosystems (npm, PyPI, Maven, Go, apt, apk, RPM)
- **Trivy**: Can generate SBOM as CycloneDX or SPDX alongside vulnerability scanning
- **SBOM Generator** (Microsoft): .NET-focused SBOM tool

```bash
# Generate CycloneDX from container image
syft alpine:latest -o cyclonedx-json > sbom-cyclonedx.json

# Generate SPDX from project directory
syft dir:/path/to/project -o spdx-json > sbom-spdx.json

# Trivy SBOM generation
trivy image --format cyclonedx --output sbom.json myapp:latest
```

### Analysis and Vulnerability Correlation

1. **Parse SBOM** → extract components with PURL (Package URL) and CPE identifiers
2. **Correlate with NVD** → query NVD 2.0 API by CPE name (most precise) or keyword
3. **Build dependency graph** → use NetworkX to trace transitive dependency chains
4. **Calculate risk scores** → Component Risk × Dependency Factor (in-degree weighted)
5. **Cross-validate with Grype** → broader advisory database coverage (NVD + GitHub + distro-specific)
6. **Generate compliance report** → structured output for EO 14028, EU CRA, SOC 2

### Key Metrics for Risk Assessment

| Metric | Meaning |
|--------|---------|
| **In-degree** | How many components depend on this one (high = high blast radius) |
| **Shortest path to root** | Distance from app entry point (closer = more exploitable) |
| **Betweenness centrality** | Components on many dependency paths (bottleneck risk) |

### Compliance Mapping

- **NIST CSF**: GV.SC-01, GV.SC-03, GV.SC-06, GV.SC-07
- **NIST AI RMF**: GOVERN-5.2, MAP-1.6, MANAGE-2.2

---

## 2. SAST/DAST/SCA Integration

### SAST (Static Application Security Testing)

Analyzes source code without execution. Best for catching vulnerability patterns early.

| Tool | Approach | Languages | Strengths |
|------|----------|-----------|-----------|
| **CodeQL** | Semantic analysis, code-as-data | 9+ languages | Deep dataflow, taint tracking |
| **Semgrep** | Pattern matching | 30+ languages | Fast, custom rules, 3000+ community rules |
| **Bandit** | AST analysis | Python | Python-specific depth |
| **Gosec** | AST analysis | Go | Go-specific patterns |

**CI/CD Integration Pattern:**
```yaml
# GitHub Actions SAST
- name: Run Semgrep
  run: |
    semgrep scan \
      --config p/security-audit \
      --config p/owasp-top-ten \
      --severity ERROR --error \
      --json --output results.json .
```

### DAST (Dynamic Application Security Testing)

Tests running applications by sending attack payloads. Finds runtime vulnerabilities SAST cannot.

| Tool | Scan Type | Speed | Best For |
|------|-----------|-------|----------|
| **OWASP ZAP** | Baseline, Full, API | 2-60 min | Web apps, REST/GraphQL APIs |
| **Nuclei** | Template-based | Fast | Specific CVE checks |

**Three ZAP scan modes:**
1. **Baseline** (2-5 min): Passive scan, spider + passive analysis — suitable for CI
2. **Full** (30-60 min): Active attack payloads — schedule for nightly
3. **API Scan**: Uses OpenAPI/Swagger spec to test all documented endpoints

### SCA (Software Composition Analysis)

Scans dependencies against vulnerability databases for known CVEs.

| Tool | Database Coverage | Free Tier | Key Feature |
|------|-------------------|-----------|-------------|
| **Snyk** | Broad (NVD, GHSA, proprietary) | 200 tests/month | Auto-fix PRs, license compliance |
| **Trivy** | NVD + distro-specific | Unlimited | Also scans containers, IaC |
| **OWASP Dep-Check** | NVD | Unlimited | NVD-focused, Java strength |
| **npm audit / pip-audit** | Ecosystem-specific | Unlimited | Quick checks |

### Quality Gates

```yaml
# Security gate aggregates all scanner results
security-gate:
  needs: [secrets-scan, sast-scan, sca-scan, container-scan]
  if: always()
  steps:
    - name: Check results
      run: |
        for job in secrets-scan sast-scan sca-scan container-scan; do
          if [[ "${{ needs.${job}.result }}" == "failure" ]]; then
            echo "BLOCKED: ${job} found critical/high vulnerabilities"
            exit 1
          fi
        done
```

**Recommended thresholds:**
- **FAIL** on Critical/High in SAST and SCA
- **WARN** on Medium (allow merge with justification)
- **IGNORE** Info/Low in CI, track in dashboard

---

## 3. Secrets Scanning in CI/CD

### Tool Comparison

| Tool | Approach | History Scan | Verified Secrets | Free |
|------|----------|-------------|-----------------|------|
| **Gitleaks** | Regex + entropy | Full git history | No | Yes (open-source) |
| **TruffleHog** | Regex + entropy + verification | Full git history + filesystem | Yes (tests against live APIs) | Yes (open-source) |
| **GitHub Secret Scanning** | Partner patterns | Push protection | Yes (partner-verified) | Public repos free |

### Gitleaks Configuration

```toml
# .gitleaks.toml
[extend]
useDefault = true

[allowlist]
paths = [
  '''(^|/)test(s)?/''',
  '''\.test\.(js|ts|py)$''',
  '''fixtures/''',
  '''node_modules/''',
]
regexes = [
  '''EXAMPLE''',
  '''test[-_]?(key|secret|token|password)''',
]

[[rules]]
id = "internal-api-token"
regex = '''(?i)x-internal-token["\s:=]+['"]?([a-zA-Z0-9_\-]{40,})['"]?'''
entropy = 3.5
keywords = ["x-internal-token"]
```

### Pipeline Integration

```yaml
# GitHub Actions
- uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

# GitLab CI
include:
  - template: Security/Secret-Detection.gitlab-ci.yml
```

### Remediation Workflow

1. **Detect** → Gitleaks/TruffleHog finds committed secret
2. **Rotate** → Immediately revoke the exposed credential at the provider
3. **Clean history** → Use `git-filter-repo` to remove from all commits
4. **Prevent** → Enable pre-commit hooks + CI/CD scanning + push rules
5. **Baseline** → For legacy repos, generate baseline to catch only new secrets

```bash
# Clean git history
git filter-repo --replace-text expressions.txt --force

# Pre-commit hook
pip install pre-commit
# .pre-commit-config.yaml → gitleaks hook
pre-commit install
```

### Verification Checklist

- [ ] Gitleaks blocks commits containing hardcoded secrets
- [ ] Pre-commit hooks catch secrets before push
- [ ] CI/CD scanning runs on every PR
- [ ] Push rules enforce secret detection as required status check
- [ ] Baseline file maintained for legacy repositories

---

## 4. Container Image Signing and Verification

### Cosign (Sigstore)

Cosign provides both **key-based** and **keyless (OIDC)** signing for container images and OCI artifacts.

| Method | Key Management | Best For |
|--------|---------------|----------|
| **Key-based** | Generated keys, stored in KMS/Vault | Long-term signing authority |
| **Keyless (OIDC)** | Short-lived certs via Fulcio + Rekor | CI/CD automation, no key management |

### Key-Based Signing

```bash
# Generate key pair
cosign generate-key-pair
# Or store in KMS
cosign generate-key-pair --kms awskms:///alias/cosign-key

# Sign image
cosign sign --key cosign.key ghcr.io/myorg/myapp:v1.0.0

# Verify
cosign verify --key cosign.pub ghcr.io/myorg/myapp:v1.0.0
```

### Keyless Signing (CI/CD)

```bash
# GitHub Actions (OIDC token automatic)
cosign sign ghcr.io/myorg/myapp@sha256:abc123... --yes

# Verify by workflow identity
cosign verify ghcr.io/myorg/myapp@sha256:abc123... \
  --certificate-identity=https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

### Attestations (SLSA Provenance)

```bash
# Generate and attach SBOM attestation
syft ghcr.io/myorg/myapp:v1.0.0 -o cyclonedx-json > sbom.json
cosign attest --key cosign.key \
  --type cyclonedx --predicate sbom.json \
  ghcr.io/myorg/myapp:v1.0.0

# Verify attestation
cosign verify-attestation --key cosign.pub \
  --type cyclonedx ghcr.io/myorg/myapp:v1.0.0
```

### Kubernetes Admission Enforcement

```yaml
# Sigstore Policy Controller
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
    - glob: "ghcr.io/myorg/**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: "https://github.com/myorg/.*"

# Kyverno integration
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences: ["ghcr.io/myorg/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

### Best Practices

1. **Sign by digest** (not tag) for immutable references
2. **Use keyless signing** in CI/CD for automated pipelines
3. **Attach SBOM attestations** alongside signatures
4. **Enforce at admission** with policy-controller or Kyverno
5. **Store keys in KMS** (never in CI/CD environment variables)
6. **Verify the full chain**: signature + certificate + Rekor inclusion

---

## 5. Supply Chain Integrity (in-toto, Cosign)

### in-toto Framework

in-toto (CNCF graduated project) ensures supply chain integrity from initiation to installation through cryptographically signed attestations at each pipeline step.

### Core Components

| Component | Purpose |
|-----------|---------|
| **Layout** | Policy document defining steps, functionaries, and expected artifacts |
| **Link Metadata** | Signed record of what happened at each step (materials, products, command) |
| **Inspection** | Client-side verification checks at deployment time |

### Supply Chain Layout Example

```python
from in_toto.models.layout import Layout, Step, Inspection

layout = Layout()
layout.set_relative_expiration(months=6)

# Step 1: Source checkout
checkout = Step(name="checkout")
checkout.expected_materials = []
checkout.expected_products = [["CREATE", "Dockerfile"], ["CREATE", "src/*"]]
checkout.pubkeys = [builder_key["keyid"]]
checkout.threshold = 1

# Step 2: Build
build = Step(name="build")
build.expected_materials = [
    ["MATCH", "Dockerfile", "WITH", "PRODUCTS", "FROM", "checkout"]
]
build.expected_products = [["CREATE", "image-digest.txt"]]
build.pubkeys = [builder_key["keyid"]]

# Step 3: Security scan
scan = Step(name="scan")
scan.expected_materials = [
    ["MATCH", "image-digest.txt", "WITH", "PRODUCTS", "FROM", "build"]
]
scan.expected_products = [["CREATE", "vulnerability-report.json"]]
scan.pubkeys = [scanner_key["keyid"]]

layout.steps = [checkout, build, scan]
```

### Pipeline Recording

```bash
# Record each step
in-toto-run --step-name checkout \
  --key keys/builder \
  --products Dockerfile src/* \
  -- git clone https://github.com/org/app.git .

in-toto-run --step-name build \
  --key keys/builder \
  --materials Dockerfile src/* \
  --products image-digest.txt \
  -- docker build -t app:latest .
```

### Verification

```bash
# Verify entire supply chain
in-toto-verify --layout root.layout \
  --layout-key keys/owner.pub \
  --link-dir ./link-metadata/
```

### SLSA Alignment

| SLSA Level | in-toto Requirement |
|------------|---------------------|
| Level 1 | Build process documented (layout exists) |
| Level 2 | Signed attestations from hosted build service |
| Level 3 | Hardened build platform, non-falsifiable provenance |
| Level 4 | Two-party review, hermetic builds |

### Code Signing for Artifacts

| Method | Tool | Key Type | Transparency Log |
|--------|------|----------|-----------------|
| GPG | gpg | Long-lived asymmetric | None (self-hosted) |
| Sigstore | cosign | OIDC ephemeral | Rekor |
| Notation | notation (Notary v2) | CA-issued | None |

---

## 6. Infrastructure as Code Scanning

### Tool Comparison

| Tool | Frameworks | Policy Language | Key Feature |
|------|-----------|----------------|-------------|
| **Checkov** | Terraform, CloudFormation, K8s, Helm, ARM, Ansible | Python, YAML | 2500+ built-in policies, graph analysis |
| **tfsec** | Terraform only | Rego | Deep HCL understanding |
| **KICS** | 15+ IaC frameworks | Rego | Multi-framework support |
| **Terrascan** | Terraform, K8s, CloudFormation | Rego | OPA-based policies |

### Checkov Integration

```yaml
# GitHub Actions
- name: Run Checkov
  uses: bridgecrewio/checkov-action@v12
  with:
    directory: terraform/
    framework: terraform
    output_format: cli,sarif
    soft_fail: false
```

### Custom Policies

```python
# custom_checks/s3_versioning.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class S3BucketVersioning(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has versioning enabled"
        id = "CKV_CUSTOM_1"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        versioning = conf.get("versioning", [{}])
        if isinstance(versioning, list) and len(versioning) > 0:
            if versioning[0].get("enabled", [False])[0]:
                return CheckResult.PASSED
        return CheckResult.FAILED
```

### Kubernetes and Helm Scanning

```bash
# Render and scan Helm templates
helm template myrelease ./mychart --values values-prod.yaml > rendered.yaml
kubesec scan rendered.yaml
checkov -f rendered.yaml --framework kubernetes
trivy config rendered.yaml
kube-linter lint rendered.yaml
```

### Key Checks to Enforce

| Check | Severity | Description |
|-------|----------|-------------|
| CKV_AWS_18 | HIGH | S3 bucket has public read ACL |
| CKV_AWS_19 | HIGH | S3 bucket not encrypted |
| CKV_AWS_24 | HIGH | CloudWatch log group not encrypted |
| CKV_AWS_79 | MEDIUM | EC2 instance metadata v1 enabled |
| CKV_AWS_145 | MEDIUM | S3 default encryption with CMK |

---

## 7. Secrets Management (Vault, KMS)

### HashiCorp Vault Architecture

| Component | Purpose |
|-----------|---------|
| **Digital Vault** | Encrypted credential storage (FIPS 140-2) |
| **CPM** | Automated password rotation and verification |
| **PSM** | Session isolation, recording, keystroke logging |
| **PVWA** | Web interface for credential management |
| **PTA** | Behavioral analytics for privileged accounts |
| **Conjur** | Application identity and secrets management |

### Dynamic Secrets Engine

```bash
# Database secrets engine
vault secrets enable database

vault write database/config/production-postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="app-readonly,app-readwrite" \
    connection_url="postgresql://{{username}}:{{password}}@db:5432/appdb" \
    username="vault_admin" password="$VAULT_DB_PASSWORD"

# Create role with TTL
vault write database/roles/app-readonly \
    db_name=production-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" max_ttl="24h"

# Test dynamic credential generation
vault read database/creds/app-readonly
# Returns: username=v-approle-app-read-xxxxx, password=<random>, lease_id=...
```

### AWS Secrets Engine

```bash
vault secrets enable aws
vault write aws/config/root access_key=... secret_key=... region=us-east-1

vault write aws/roles/s3-readonly \
    credential_type=iam_user \
    policy_document=@s3-readonly-policy.json

vault write aws/roles/ec2-admin \
    credential_type=assumed_role \
    role_arns="arn:aws:iam::123456789012:role/VaultEC2AdminRole" \
    default_sts_ttl="30m"
```

### PKI Secrets Engine

```bash
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal common_name="Corp Root CA" ttl=87600h

vault secrets enable -path=pki_int pki
vault write pki_int/roles/web-server \
    allowed_domains="corp.local" allow_subdomains=true max_ttl=720h

vault write pki_int/issue/web-server common_name="api.corp.local" ttl=720h
```

### AWS KMS Envelope Encryption

```python
# Generate data encryption key
response = kms.generate_data_key(
    KeyId='alias/my-key',
    KeySpec='AES_256'
)

# Encrypt data with plaintext DEK
plaintext_key = response['Plaintext']  # Use immediately
encrypted_key = response['CiphertextBlob']  # Store with ciphertext

cipher = AES.new(plaintext_key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(data)

# Store: encrypted_key + ciphertext + tag + nonce
# Discard plaintext_key from memory
```

### Kubernetes Integration

```yaml
# Vault Agent Injector annotations
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "web-app"
        vault.hashicorp.com/agent-inject-secret-db-creds: "database/creds/readonly"
```

### Authentication Methods

| Method | Use Case | Security Level |
|--------|----------|---------------|
| **AppRole** | Machine-to-machine (CI/CD, apps) | High (role_id + secret_id) |
| **OIDC** | Human users via SSO | High (SSO-integrated) |
| **Kubernetes** | Pod-based access | High (service account bound) |
| **AWS IAM** | AWS-native workloads | High (IAM role bound) |

---

## 8. Privileged Access Management

### CyberArk Architecture

| Component | Function |
|-----------|----------|
| **Digital Vault** | Encrypted credential storage |
| **Central Policy Manager (CPM)** | Automated rotation and verification |
| **Privileged Session Manager (PSM)** | Session isolation and recording |
| **Privileged Threat Analytics (PTA)** | Behavioral analytics |
| **Secure Cloud Access (SCA)** | Ephemeral cloud roles |

### Zero Standing Privilege (ZSP)

**TEA Framework**: Time, Entitlements, Approvals govern every privileged session.

```
User requests access
  → CyberArk evaluates against TEA policies
  → Approval workflow (auto/manager/multi-level)
  → Ephemeral IAM role created in target cloud
  → Time-bound session (15min - 8hr)
  → All actions logged and recorded
  → Session expires → role deleted → zero standing privileges remain
```

### Just-In-Time Access Models

| Model | Description | Example |
|-------|-------------|---------|
| **Broker and Remove** | Grant through approval, auto-remove after window | Cloud console access |
| **Elevation on Demand** | Base access → elevate on request | sudo elevation |
| **Account Creation/Deletion** | Temporary account, destroyed after use | Vendor access |
| **Group Membership Toggle** | Add to privileged group temporarily | DBA access |

### JIT Migration Phases

```
Phase 1: DISCOVERY (Weeks 1-2)
  - Inventory all standing privileged roles
  - Map users to standing role assignments
  - Analyze actual permission usage (CloudTrail)

Phase 2: POLICY CREATION (Weeks 3-4)
  - Create ZSP policies based on actual usage
  - Define TEA parameters per policy
  - Configure approval workflows

Phase 3: MIGRATION (Weeks 5-8)
  - Pilot with select group
  - Remove standing privileges incrementally
  - Monitor and adjust policies

Phase 4: GOVERNANCE (Ongoing)
  - Monthly policy effectiveness review
  - Quarterly entitlement optimization
  - Report ZSP metrics to leadership
```

### Database PAM

- **Session proxy**: Users connect through PSM, never directly to database
- **Credential vaulting**: DBA passwords stored in vault, checked out per session
- **Query auditing**: All SQL statements logged with user identity
- **Dynamic credentials**: Vault generates short-lived DB credentials per session

---

## 9. Secure SDLC Practices

### DevSecOps Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  DEVELOPMENT        BUILD           TEST          DEPLOY        │
│                                                                 │
│  Pre-commit    →  SAST Scan    →  Unit Tests  →  Staging       │
│  (Gitleaks)       (Semgrep)       (Coverage)    (Deploy)       │
│                                                                 │
│  Code Review   →  SCA Scan     →  DAST Scan   →  Production    │
│  (PR Reviews)     (Trivy/Snyk)    (ZAP)         (Canary)       │
│                                                                 │
│  IDE Plugins   →  Container    →  IaC Scan    →  Admission     │
│  (Semgrep)        Scan (Trivy)    (Checkov)      Control       │
│                                                     (Cosign)    │
└─────────────────────────────────────────────────────────────────┘
```

### GitHub Actions Security Hardening

| Control | Implementation |
|---------|---------------|
| **SHA pinning** | Pin actions to immutable commit SHA, not mutable tags |
| **Minimal permissions** | `permissions: {}` at workflow level, grant per-job |
| **Script injection prevention** | Use env vars, not `${{ }}` interpolation in `run` steps |
| **Fork PR safety** | Avoid `pull_request_target`; if needed, never checkout PR code |
| **Secret protection** | Use environment protection rules, never echo secrets |
| **Change controls** | CODEOWNERS on `.github/workflows/`, Dependabot for SHA updates |

### GitLab CI Security Templates

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: DAST.gitlab-ci.yml
  - template: Security/License-Scanning.gitlab-ci.yml
```

### Application Runtime Protection

| Layer | Tool | Purpose |
|-------|------|---------|
| **RASP** | OpenRASP | Detects/block attacks at function level (SQLi, XSS, RCE) |
| **App Whitelisting** | AppLocker (Windows) | Only pre-approved binaries execute |
| **Memory Protection** | DEP + ASLR + CFG | Prevents buffer overflow, ROP chains |

### LLM Security Guardrails

For AI-powered applications:
- **Input rails**: Block prompt injection, redact PII, enforce topic boundaries
- **Output rails**: Detect hallucinations, filter toxic content, validate schemas
- **Tools**: NVIDIA NeMo Guardrails (Colang), Guardrails AI, Microsoft Presidio

### Container Registry Security

| Control | Implementation |
|---------|---------------|
| **Vulnerability scanning** | Trivy on push, continuous scanning of deployed images |
| **Image signing** | Cosign keyless in CI/CD, enforce at K8s admission |
| **SBOM attachment** | cosign attach sbom for every promoted image |
| **Tag immutability** | ECR/ACR immutable tags for release versions |
| **Content trust** | Harbor content trust policy blocks unsigned pulls |
| **Lifecycle policies** | Auto-expire untagged images after 7 days |

### Harbor Registry Configuration

```yaml
# Key security features
trivy:
  enabled: true
  severity: "CRITICAL,HIGH,MEDIUM"
  autoScan: true

# Content trust enforcement
metadata:
  enable_content_trust: "true"
  enable_content_trust_cosign: "true"

# Vulnerability prevention
metadata:
  prevent_vul: "true"
  severity: "critical"
```

### AWS Nitro Enclave (Confidential Computing)

For workloads requiring hardware-level isolation:
- Enclave has no network, no storage, no interactive access
- KMS attestation-based decryption (PCR conditions)
- Communication only through vsock
- Use cases: PII tokenization, cryptographic key management, PHI processing

---

## 10. Tool Matrix

### Supply Chain Security

| Category | Tool | License | Key Capability |
|----------|------|---------|---------------|
| SBOM Generation | Syft | Apache-2.0 | 30+ ecosystem support |
| SBOM Analysis | Grype | Apache-2.0 | Multi-database vuln correlation |
| SAST | Semgrep | LGPL-2.1 | Pattern matching, custom rules |
| SAST | CodeQL | Proprietary (free for public) | Semantic analysis, taint tracking |
| DAST | OWASP ZAP | Apache-2.0 | Web app + API scanning |
| SCA | Snyk | Commercial (free tier) | Auto-fix PRs, license compliance |
| SCA | Trivy | Apache-2.0 | Containers, FS, IaC, SBOM |
| Secrets | Gitleaks | MIT | Regex + entropy detection |
| Secrets | TruffleHog | AGPL-3.0 | Verified secret detection |
| IaC Scanning | Checkov | Apache-2.0 | 2500+ policies, graph analysis |
| IaC Scanning | tfsec | Apache-2.0 | Terraform-focused |
| Image Signing | Cosign | Apache-2.0 | Sigstore keyless signing |
| Supply Chain | in-toto | Apache-2.0 | End-to-end integrity verification |
| Registry | Harbor | Apache-2.0 | Trivy integration, RBAC, content trust |
| Secrets Mgmt | HashiCorp Vault | BSL (free tier) | Dynamic secrets, PKI, transit |
| Encryption | AWS KMS | Commercial | Envelope encryption, Nitro attestation |
| PAM | CyberArk | Commercial | Vault, PSM, ZSP, SCA |

---

## 11. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

- [ ] Enable pre-commit hooks (Gitleaks + Semgrep)
- [ ] Add SAST to CI/CD (Semgrep or CodeQL)
- [ ] Add dependency scanning (Trivy or Snyk)
- [ ] Generate SBOMs for all container images
- [ ] Enable branch protection with security status checks

### Phase 2: Pipeline Security (Weeks 5-8)

- [ ] Add container vulnerability scanning (Trivy)
- [ ] Implement container image signing (Cosign)
- [ ] Add IaC scanning (Checkov or tfsec)
- [ ] Configure security quality gates
- [ ] Harden CI/CD workflows (SHA pinning, minimal permissions)

### Phase 3: Advanced Controls (Weeks 9-16)

- [ ] Deploy DAST scanning (ZAP baseline on staging)
- [ ] Implement supply chain integrity (in-toto or SLSA)
- [ ] Deploy secrets management (Vault dynamic secrets)
- [ ] Configure K8s admission control for image verification
- [ ] Implement PAM for database and cloud access

### Phase 4: Maturity (Weeks 17-24)

- [ ] Zero standing privilege implementation
- [ ] JIT access provisioning for privileged access
- [ ] Continuous monitoring and compliance reporting
- [ ] Threat hunting for supply chain compromise
- [ ] Incident response playbook for supply chain attacks

---

## 12. Common Pitfalls

### SBOM & Dependency Scanning
- **Incomplete SBOMs**: Vendor SBOMs may miss shaded/bundled JARs containing vulnerable libraries
- **NVD rate limits**: Without API key, limited to 5 requests/30 seconds
- **Transitive blind spots**: Ignoring transitive vulnerabilities because "we don't call that function"

### CI/CD Security
- **Alert fatigue**: 40%+ false positive rates destroy developer trust; target <15%
- **Over-suppressing rules**: Can create blind spots against OWASP Top 10
- **Mutable action tags**: `@v3` can be overwritten by attackers; always pin to SHA
- **pull_request_target**: Runs with base repo permissions on fork PRs — extremely dangerous

### Container Security
- **Tag mutability**: `latest` tag can point to different images; always use digests for production
- **Build-time only scanning**: New CVEs discovered after build; implement continuous scanning
- **Debug mode in production**: Nitro Enclave debug mode breaks confidentiality guarantee

### Secrets Management
- **Not rotating original credentials**: After Vault migration, old static credentials remain valid
- **TTL too short**: Causes credential expiry mid-deployment for long-running jobs
- **Plaintext DEK in memory**: Always wipe after use; never log or persist

### PAM & Access Control
- **Skipping audit mode**: Deploying AppLocker in Enforce mode without audit period causes outages
- **Path rules for AppLocker**: Users can place files in allowed paths; prefer publisher rules
- **No break-glass procedure**: Vault/PAM unavailability must not lock out operators
- **Long JIT time windows**: Negates zero standing privilege benefits

---

## References

- [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/pubs/ssdf/1.0/final)
- [SLSA Framework](https://slsa.dev/)
- [OWASP SBOM Guide](https://owasp.org/www-project-software-bill-of-materials/)
- [in-toto](https://in-toto.io/)
- [Sigstore](https://www.sigstore.dev/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)

---

*This document synthesizes knowledge from 30 Anthropic Cybersecurity Skills covering the full spectrum of supply chain security, DevSecOps, and secure development practices. Each section references specific tools, configurations, and workflows validated across real-world enterprise environments.*
