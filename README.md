<div align="center">

# 🔐 Cyber Mastery Library

### The Complete Offensive & Defensive Security Knowledge Base

**754 skills. 14 synthesis docs. ~400KB of structured cybersecurity knowledge.**
**Built from the ground up — not scraped, not hallucinated.**

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-754-blue.svg)](#-skills-library)
[![Docs](https://img.shields.io/badge/docs-14-orange.svg)](#-synthesis-documents)
[![Size](https://img.shields.io/badge/size-~400KB-red.svg)](#-what-inside)

</div>

---

## What Is This?

A **curated cybersecurity knowledge base** — 754 individual skill documents covering every major security domain, synthesized into 14 comprehensive reference guides. Each skill contains practical tool commands, attack methodologies, and detection techniques. The synthesis docs tie everything together into cohesive, cross-referenced guides.

**Not a tool. Not a framework. A knowledge base you actually want to read.**

---

## 📊 At a Glance

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   754  Individual skill documents                       │
│   14   Synthesis reference guides                       │
│   45MB Total raw skill content                          │
│   400KB Curated synthesis library                       │
│   11K+ Lines of structured knowledge                    │
│                                                         │
│   Recon → Exploitation → Post-Ex → Persistence          │
│   Detection → Hunting → Forensics → Response             │
│   Cloud → Containers → Identity → Zero Trust             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📚 Synthesis Documents

The crown jewels — 14 documents that synthesize hundreds of skills into actionable reference guides.

### ⚔️ Offensive Security

| # | Document | Size | What It Covers |
|---|----------|------|----------------|
| 1 | [Recon & OSINT](offensive/recon-osint-mastery.md) | 45KB | Passive/active recon, DNS enumeration, subdomain discovery, Shodan, SpiderFoot, BloodHound, certificate transparency, IOC collection |
| 2 | [Network Pentest](offensive/network-pentest-mastery.md) | 21KB | Nmap scanning, MITM attacks, ARP spoofing, SSL stripping, VLAN hopping, WiFi cracking, Zeek analysis, C2 beaconing detection |
| 3 | [Web App Pentest](offensive/webapp-pentest-mastery.md) | 25KB | SQL injection, XSS, XXE, SSRF, JWT attacks, WAF bypass, API/GraphQL testing, business logic flaws, CSP bypass |
| 4 | [Exploitation & Post-Ex](offensive/exploitation-postex-mastery.md) | 30KB | Metasploit, privilege escalation (Linux + Windows), credential harvesting, lateral movement, social engineering, phishing campaigns |
| 5 | [AD & Windows](offensive/ad-windows-pentest-mastery.md) | 26KB | Kerberos attacks, NTLM relay, ADCS (ESC1-8), DCSync, BloodHound, PowerShell attacks, Azure AD, event log analysis |
| 6 | [Malware Analysis](offensive/malware-analysis-mastery.md) | 23KB | Static/dynamic analysis, Ghidra, YARA rules, C2 infrastructure, ransomware, deobfuscation, IOC extraction |
| 7 | [Mobile & IoT](offensive/mobile-iot-pentest-mastery.md) | 17KB | Android/iOS testing, Frida, certificate pinning bypass, SCADA/ICS protocols, firmware extraction, OT security |

### 🛡️ Defensive Security

| # | Document | Size | What It Covers |
|---|----------|------|----------------|
| 8 | [DFIR](defensive/dfir-mastery.md) | 27KB | Incident response lifecycle, disk/memory forensics, timeline reconstruction, Windows/Linux artifacts, cloud forensics, evidence chain |
| 9 | [Detection Engineering](defensive/detection-engineering-mastery.md) | 31KB | Splunk SPL rules, Sigma rules, detection-as-code, EDR, osquery, purple team operations, Atomic Red Team, SOC dashboards |
| 10 | [Threat Intel & Hunting](defensive/threat-intel-mastery.md) | 34KB | MITRE ATT&CK, MISP, STIX/TAXII, threat hunting methodology, adversary profiling, dark web monitoring, CTI reports |

### 🏗️ Architecture & Governance

| # | Document | Size | What It Covers |
|---|----------|------|----------------|
| 11 | [Cloud & Containers](architecture/cloud-container-pentest-mastery.md) | 36KB | AWS/GCP/Azure attack paths, Docker/K8s security, container escape, honeypots, deception technology |
| 12 | [Crypto, API & Infra](architecture/crypto-api-infra-mastery.md) | 33KB | TLS/SSL, JWT, WAF, IDS/IPS, DDoS mitigation, zero trust networking, API security testing |
| 13 | [Supply Chain & DevSecOps](architecture/supplychain-devsecops-mastery.md) | 31KB | SBOM, SAST/DAST/SCA, secrets scanning, Vault, Cosign, in-toto, CI/CD hardening |
| 14 | [Identity & Zero Trust](architecture/identity-zero-trust-mastery.md) | 28KB | SSO/SAML, MFA/FIDO2, PAM, microsegmentation, ZTNA, identity governance, JIT access |

---

## 🧰 Skills Library

**754 individual skill documents** organized by domain. Each skill contains:
- Step-by-step methodology
- Tool commands with examples
- Common pitfalls and gotchas
- MITRE ATT&CK mappings (where applicable)
- Detection signatures for blue team

<details>
<summary><strong>🔍 Reconnaissance & OSINT (26 skills)</strong></summary>

`acquiring-disk-image-with-dd-and-dcfldd` · `analyzing-certificate-transparency-for-phishing` · `analyzing-typosquatting-domains-with-dnstwist` · `collecting-indicators-of-compromise` · `collecting-open-source-intelligence` · `conducting-external-reconnaissance-with-osint` · `performing-brand-monitoring-for-impersonation` · `performing-dns-enumeration-and-zone-transfer` · `performing-ip-reputation-analysis-with-shodan` · `performing-open-source-intelligence-gathering` · `performing-osint-with-spiderfoot` · `performing-subdomain-enumeration-with-subfinder` · `security-org-reconnaissance` · `analyzing-indicators-of-compromise` · `performing-active-directory-bloodhound-analysis` · `conducting-domain-persistence-with-dcsync` · ...

</details>

<details>
<summary><strong>🌐 Network Security (60 skills)</strong></summary>

`conducting-network-penetration-test` · `scanning-network-with-nmap-advanced` · `performing-network-forensics-with-wireshark` · `performing-network-traffic-analysis-with-tshark` · `performing-network-traffic-analysis-with-zeek` · `performing-arp-spoofing-attack-simulation` · `conducting-man-in-the-middle-attack-simulation` · `performing-ssl-stripping-attack` · `performing-vlan-hopping-attack` · `conducting-wireless-network-penetration-test` · `performing-wifi-password-cracking-with-aircrack` · `performing-bluetooth-security-assessment` · `detecting-beaconing-patterns-with-zeek` · `detecting-network-anomalies-with-zeek` · `implementing-network-traffic-baselining` · `performing-network-packet-capture-analysis` · `detecting-network-scanning-with-ids-signatures` · ...

</details>

<details>
<summary><strong>💉 Web Application Security (32 skills)</strong></summary>

`performing-web-application-penetration-test` · `testing-for-xss-vulnerabilities` · `testing-for-xss-vulnerabilities-with-burpsuite` · `exploiting-sql-injection-vulnerabilities` · `exploiting-sql-injection-with-sqlmap` · `testing-for-open-redirect-vulnerabilities` · `testing-for-broken-access-control` · `testing-cors-misconfiguration` · `exploiting-server-side-request-forgery` · `performing-ssrf-vulnerability-exploitation` · `testing-for-xxe-injection-vulnerabilities` · `exploiting-insecure-deserialization` · `testing-for-json-web-token-vulnerabilities` · `performing-jwt-none-algorithm-attack` · `performing-web-application-firewall-bypass` · `performing-content-security-policy-bypass` · `performing-directory-traversal-testing` · `testing-for-business-logic-vulnerabilities` · `performing-api-security-testing-with-postman` · `performing-graphql-security-assessment` · `exploiting-websocket-vulnerabilities` · ...

</details>

<details>
<summary><strong>💥 Exploitation & Post-Exploitation (67 skills)</strong></summary>

`exploiting-vulnerabilities-with-metasploit-framework` · `performing-privilege-escalation-on-linux` · `performing-privilege-escalation-assessment` · `detecting-credential-dumping-techniques` · `performing-kerberoasting-attack` · `exploiting-kerberoasting-with-impacket` · `conducting-pass-the-ticket-attack` · `detecting-pass-the-hash-attacks` · `performing-lateral-movement-with-wmiexec` · `performing-lateral-movement-detection` · `extracting-credentials-from-memory-dump` · `performing-credential-access-with-lazagne` · `deploying-active-directory-honeytokens` · `deploying-decoy-files-for-ransomware-detection` · `performing-ransomware-response` · `conducting-social-engineering-penetration-test` · `conducting-spearphishing-simulation-campaign` · `performing-red-team-phishing-with-gophish` · ...

</details>

<details>
<summary><strong>🏢 Active Directory & Windows (38 skills)</strong></summary>

`performing-active-directory-penetration-test` · `performing-active-directory-vulnerability-assessment` · `conducting-internal-reconnaissance-with-bloodhound-ce` · `exploiting-active-directory-with-bloodhound` · `exploiting-active-directory-certificate-services-esc1` · `detecting-golden-ticket-attacks-in-kerberos-logs` · `detecting-kerberoasting-attacks` · `detecting-dcsync-attack-in-active-directory` · `conducting-domain-persistence-with-dcsync` · `detecting-pass-the-hash-attacks` · `detecting-pass-the-ticket-attacks` · `analyzing-windows-event-logs-in-splunk` · `analyzing-powershell-script-block-logging` · `detecting-suspicious-powershell-execution` · `hunting-for-persistence-mechanisms-in-windows` · `detecting-mimikatz-execution-patterns` · `analyzing-active-directory-acl-abuse` · ...

</details>

<details>
<summary><strong>🧬 Malware Analysis (66 skills)</strong></summary>

`analyzing-android-malware-with-apktool` · `analyzing-bootkit-and-rootkit-samples` · `analyzing-cobalt-strike-beacon-configuration` · `analyzing-cobaltstrike-malleable-c2-profiles` · `analyzing-command-and-control-communication` · `analyzing-golang-malware-with-ghidra` · `analyzing-linux-elf-malware` · `analyzing-macro-malware-in-office-documents` · `analyzing-malicious-pdf-with-peepdf` · `analyzing-malware-behavior-with-cuckoo-sandbox` · `analyzing-packed-malware-with-upx-unpacker` · `analyzing-ransomware-encryption-mechanisms` · `deobfuscating-javascript-malware` · `deobfuscating-powershell-obfuscated-malware` · `reverse-engineering-malware-with-ghidra` · `reverse-engineering-dotnet-malware-with-dnspy` · `performing-malware-triage-with-yara-rules` · `performing-yara-rule-development-for-detection` · ...

</details>

<details>
<summary><strong>📱 Mobile & IoT Security (26 skills)</strong></summary>

`analyzing-android-malware-with-apktool` · `analyzing-ios-app-security-with-objection` · `performing-android-app-static-analysis-with-mobsf` · `performing-dynamic-analysis-of-android-app` · `performing-ios-app-security-assessment` · `performing-mobile-app-certificate-pinning-bypass` · `reverse-engineering-android-malware-with-jadx` · `reverse-engineering-ios-app-with-frida` · `performing-iot-security-assessment` · `performing-plc-firmware-security-analysis` · `performing-s7comm-protocol-security-analysis` · `detecting-modbus-protocol-anomalies` · `implementing-ics-firewall-with-tofino` · `performing-firmware-extraction-with-binwalk` · ...

</details>

<details>
<summary><strong>🔬 Digital Forensics & Incident Response (43 skills)</strong></summary>

`acquiring-disk-image-with-dd-and-dcfldd` · `analyzing-disk-image-with-autopsy` · `performing-memory-forensics-with-volatility3-plugins` · `performing-timeline-reconstruction-with-plaso` · `analyzing-windows-event-logs-in-splunk` · `analyzing-windows-amcache-artifacts` · `analyzing-windows-registry-for-artifacts` · `analyzing-windows-shellbag-artifacts` · `analyzing-lnk-file-and-jump-list-artifacts` · `analyzing-prefetch-files-for-execution-history` · `extracting-windows-event-logs-artifacts` · `performing-linux-log-forensics-investigation` · `performing-file-carving-with-foremost` · `analyzing-email-headers-for-phishing-investigation` · ...

</details>

<details>
<summary><strong>🚨 Detection & Monitoring (127 skills)</strong></summary>

`building-detection-rule-with-splunk-spl` · `building-detection-rules-with-sigma` · `implementing-siem-use-cases-for-detection` · `performing-false-positive-reduction-in-siem` · `implementing-endpoint-detection-with-wazuh` · `deploying-osquery-for-endpoint-monitoring` · `configuring-snort-ids-for-intrusion-detection` · `configuring-suricata-for-network-monitoring` · `implementing-runtime-security-with-tetragon` · `implementing-ebpf-security-monitoring` · `performing-purple-team-exercise` · `performing-purple-team-atomic-testing` · `performing-threat-emulation-with-atomic-red-team` · `building-incident-response-dashboard` · `implementing-alert-fatigue-reduction` · `hunting-for-beaconing-with-frequency-analysis` · `hunting-for-cobalt-strike-beacons` · `hunting-for-data-exfiltration-indicators` · ...

</details>

<details>
<summary><strong>🕵️ Threat Intelligence & Hunting (60 skills)</strong></summary>

`analyzing-threat-actor-ttps-with-mitre-attack` · `analyzing-apt-group-with-mitre-navigator` · `analyzing-cyber-kill-chain` · `building-threat-intelligence-platform` · `building-threat-feed-aggregation-with-misp` · `collecting-threat-intelligence-with-misp` · `implementing-stix-taxii-feed-integration` · `building-threat-actor-profile-from-osint` · `profiling-threat-actor-groups` · `tracking-threat-actor-infrastructure` · `monitoring-darkweb-sources` · `building-threat-hunt-hypothesis-framework` · `performing-threat-hunting-with-yara-rules` · `generating-threat-intelligence-reports` · ...

</details>

<details>
<summary><strong>☁️ Cloud & Container Security (96 skills)</strong></summary>

`performing-cloud-penetration-testing-with-pacu` · `performing-aws-account-enumeration-with-scout-suite` · `performing-aws-privilege-escalation-assessment` · `detecting-aws-iam-privilege-escalation` · `auditing-gcp-iam-permissions` · `detecting-misconfigured-azure-storage` · `detecting-azure-service-principal-abuse` · `performing-container-escape-detection` · `performing-docker-bench-security-assessment` · `performing-kubernetes-penetration-testing` · `performing-kubernetes-cis-benchmark-with-kube-bench` · `scanning-container-images-with-grype` · `hardening-docker-containers-for-production` · `implementing-honeypot-for-ransomware-detection` · ...

</details>

<details>
<summary><strong>🔐 Crypto, API & Infrastructure (53 skills)</strong></summary>

`configuring-tls-1-3-for-secure-communications` · `performing-ssl-tls-security-assessment` · `configuring-certificate-authority-with-openssl` · `exploiting-jwt-algorithm-confusion-attack` · `implementing-jwt-signing-and-verification` · `conducting-api-security-testing` · `implementing-api-rate-limiting-and-throttling` · `performing-api-fuzzing-with-restler` · `configuring-pfsense-firewall-rules` · `configuring-snort-ids-for-intrusion-detection` · `implementing-ddos-mitigation-with-cloudflare` · `implementing-cloud-waf-rules` · `implementing-zero-trust-network-access` · ...

</details>

<details>
<summary><strong>🔗 Supply Chain & DevSecOps (61 skills)</strong></summary>

`analyzing-sbom-for-supply-chain-vulnerabilities` · `building-devsecops-pipeline-with-gitlab-ci` · `integrating-sast-into-github-actions-pipeline` · `integrating-dast-with-owasp-zap-in-pipeline` · `implementing-secret-scanning-with-gitleaks` · `implementing-image-provenance-verification-with-cosign` · `implementing-supply-chain-security-with-in-toto` · `implementing-hashicorp-vault-dynamic-secrets` · `implementing-privileged-access-management-with-cyberark` · `implementing-just-in-time-access-provisioning` · ...

</details>

<details>
<summary><strong>🆔 Identity & Zero Trust (34 skills)</strong></summary>

`implementing-zero-trust-in-cloud` · `implementing-zero-trust-network-access` · `implementing-zero-trust-with-beyondcorp` · `implementing-cisa-zero-trust-maturity-model` · `implementing-multi-factor-authentication-with-duo` · `implementing-passwordless-authentication-with-fido2` · `implementing-saml-sso-with-okta` · `implementing-identity-governance-with-sailpoint` · `deploying-tailscale-for-zero-trust-vpn` · `deploying-cloudflare-access-for-zero-trust` · `implementing-microsegmentation-with-guardicore` · ...

</details>

---

## 🗺️ Reading Paths

**For Pentesters:**
```
Recon → Network → Web App → Exploitation → AD/Windows → Mobile/IoT → Malware
```

**For Blue Team:**
```
Detection Engineering → Threat Intel → DFIR → Cloud Security → Identity
```

**For Architects:**
```
Cloud/Containers → Identity/Zero Trust → Supply Chain → Crypto/API/Infra
```

**For Full Coverage:**
```
Start with any synthesis doc → Read cross-references → Dive into individual skills
```

---

## 🔧 What Makes This Different

| Feature | This Library | Other Resources |
|---------|-------------|-----------------|
| **Practical** | Actual tool commands, not theory | "You should use Nmap" |
| **Synthesized** | 754 skills → 14 coherent guides | Scattered blog posts |
| **Offensive + Defensive** | Both perspectives in every doc | One or the other |
| **ATT&CK Mapped** | Techniques linked to IDs | Ad hoc references |
| **Cross-Referenced** | Docs link to each other | Isolated articles |
| **Free** | MIT licensed | Paywalled courses |

---

## 📁 Repository Structure

```
cyber-mastery/
├── offensive/                    # ⚔️ 7 synthesis docs
│   ├── recon-osint-mastery.md
│   ├── network-pentest-mastery.md
│   ├── webapp-pentest-mastery.md
│   ├── exploitation-postex-mastery.md
│   ├── ad-windows-pentest-mastery.md
│   ├── malware-analysis-mastery.md
│   └── mobile-iot-pentest-mastery.md
├── defensive/                    # 🛡️ 3 synthesis docs
│   ├── dfir-mastery.md
│   ├── detection-engineering-mastery.md
│   └── threat-intel-mastery.md
├── architecture/                 # 🏗️ 4 synthesis docs
│   ├── cloud-container-pentest-mastery.md
│   ├── crypto-api-infra-mastery.md
│   ├── supplychain-devsecops-mastery.md
│   └── identity-zero-trust-mastery.md
├── skills/                       # 🧰 754 individual skills
│   ├── acquiring-disk-image-with-dd-and-dcfldd/
│   │   └── SKILL.md
│   ├── analyzing-active-directory-acl-abuse/
│   │   └── SKILL.md
│   └── ... (752 more)
├── README.md
├── LICENSE
└── STRUCTURE.md
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/ghassan-gaidi/cyber-mastery.git
cd cyber-mastery

# Read a synthesis doc
cat offensive/webapp-pentest-mastery.md

# Search skills for a specific topic
grep -rl "Kerberoasting" skills/ | head -5

# Find all skills related to a tool
grep -rl "sqlmap" skills/ | head -10
```

---

## 🤝 Contributing

This is a living knowledge base. Contributions welcome:

- **🔧 Corrections** — Found something wrong? Open an issue
- **📝 Updates** — New techniques or tools? Submit a PR
- **🌐 Translations** — Help make this accessible globally
- **➕ New Skills** — Add skills for missing domains

---

## 📜 License

[MIT](LICENSE) — Use it, fork it, build on it. Attribution appreciated but not required.

---

<div align="center">

**Built by [Cyrus](https://github.com/ghassan-gaidi) — an autonomous AI agent and its human partner.**

*The knowledge is free. What you build with it is yours.*

</div>
