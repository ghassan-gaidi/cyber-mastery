# Cyber Mastery Library

**~400KB of structured cybersecurity knowledge — offensive, defensive, and architectural. Built from 300+ skills, synthesized into 14 reference documents.**

Not a tool. Not a framework. A *knowledge base* — the kind of thing you bookmark and come back to.

---

## What's Inside

### Offensive Security (7 docs)

| Document | Size | Covers |
|----------|------|--------|
| [Recon & OSINT](offensive/recon-osint-mastery.md) | 45KB | Passive/active recon, DNS enum, subdomain discovery, Shodan, SpiderFoot, BloodHound, CT logs, IOC collection |
| [Network Pentest](offensive/network-pentest-mastery.md) | 21KB | Nmap, MITM, ARP spoofing, SSL stripping, VLAN hopping, WiFi cracking, Zeek, C2 beaconing detection |
| [Web App Pentest](offensive/webapp-pentest-mastery.md) | 25KB | SQLi, XSS, XXE, SSRF, JWT attacks, WAF bypass, API/GraphQL testing, business logic flaws |
| [Exploitation & Post-Ex](offensive/exploitation-postex-mastery.md) | 30KB | Metasploit, privilege escalation, credential harvesting, lateral movement, social engineering, phishing |
| [AD & Windows](offensive/ad-windows-pentest-mastery.md) | 26KB | Kerberos attacks, NTLM relay, ADCS (ESC1-8), DCSync, BloodHound, PowerShell, Azure AD |
| [Malware Analysis](offensive/malware-analysis-mastery.md) | 23KB | Static/dynamic analysis, Ghidra, YARA, C2 infra, ransomware, deobfuscation, IOC extraction |
| [Mobile & IoT](offensive/mobile-iot-pentest-mastery.md) | 17KB | Android/iOS testing, Frida, certificate pinning, SCADA/ICS, firmware extraction, OT security |

### Defensive Security (3 docs)

| Document | Size | Covers |
|----------|------|--------|
| [DFIR](defensive/dfir-mastery.md) | 27KB | Incident response, disk/memory forensics, timeline reconstruction, Windows/Linux artifacts, cloud forensics |
| [Detection Engineering](defensive/detection-engineering-mastery.md) | 31KB | Splunk SPL, Sigma rules, detection-as-code, EDR, osquery, purple team, Atomic Red Team |
| [Threat Intel & Hunting](defensive/threat-intel-mastery.md) | 34KB | MITRE ATT&CK, MISP, STIX/TAXII, threat hunting, adversary profiling, dark web monitoring |

### Architecture & Governance (4 docs)

| Document | Size | Covers |
|----------|------|--------|
| [Cloud & Containers](architecture/cloud-container-pentest-mastery.md) | 36KB | AWS/GCP/Azure attack paths, Docker/K8s security, container escape, honeypots, deception |
| [Crypto, API & Infra](architecture/crypto-api-infra-mastery.md) | 33KB | TLS/SSL, JWT, WAF, IDS/IPS, DDoS mitigation, zero trust networking, API security |
| [Supply Chain & DevSecOps](architecture/supplychain-devsecops-mastery.md) | 31KB | SBOM, SAST/DAST/SCA, secrets scanning, Vault, Cosign, in-toto, CI/CD hardening |
| [Identity & Zero Trust](architecture/identity-zero-trust-mastery.md) | 28KB | SSO/SAML, MFA/FIDO2, PAM, microsegmentation, ZTNA, identity governance, JIT access |

**Total: ~400KB | 11,247 lines | 14 documents**

---

## Quick Start

```
git clone https://github.com/leo2574/cyber-mastery.git
cd cyber-mastery
```

**For pentesters**: Start with `offensive/recon-osint-mastery.md` → `offensive/webapp-pentest-mastery.md` → `offensive/exploitation-postex-mastery.md`

**For blue team**: Start with `defensive/detection-engineering-mastery.md` → `defensive/threat-intel-mastery.md` → `defensive/dfir-mastery.md`

**For architects**: Start with `architecture/cloud-container-pentest-mastery.md` → `architecture/identity-zero-trust-mastery.md`

Each document is self-contained but cross-references others where topics overlap.

---

## What Makes This Different

- **Practical, not theoretical** — Every doc contains actual tool commands, attack chains, and detection queries. Not "you should use Nmap" but *how* to use Nmap for specific scenarios.
- **MITRE ATT&CK mapped** — Offensive techniques map to ATT&CK IDs. Detection queries reference specific techniques.
- **Offensive + Defensive perspective** — Each doc covers both the attack and the detection. Know how to break it *and* how to defend it.
- **Synthesized, not scraped** — Built from 300+ structured skill documents, not copy-pasted from random blog posts. Each doc is a synthesis of curated expert knowledge.
- **Cross-referenced** — Topics that span multiple docs (e.g., Kerberos appears in AD pentest AND detection engineering) are covered from each doc's unique angle.

---

## How It Was Built

15 parallel AI agents processed 300+ cybersecurity skill documents across 5 waves
Each agent loaded skills in its domain, extracted methodologies and tool usage, and synthesized a comprehensive reference guide
Results were indexed, cross-referenced, and organized into this library

The source skills cover the full ATT&CK spectrum plus cloud, mobile, IoT, DevSecOps, and identity governance.

---

## Use Cases

- **Pentest reference** — Look up attack techniques, tool commands, and bypass methods during engagements
- **Detection engineering** — Write Splunk/Sigma rules based on known attack patterns
- **Threat hunting** — Use the hunting methodology and hypothesis frameworks
- **Study guide** — Structured learning path from recon through post-exploitation
- **Architecture review** — Cloud security, zero trust, and DevSecOps patterns
- **Interview prep** — Comprehensive coverage of security domains

---

## Contributing

This is a living knowledge base. Contributions welcome:

- **Corrections** — Found something wrong? Open an issue
- **Updates** — New techniques, tools, or ATT&CK additions? PR welcome
- **New domains** — Want to add a doc for a missing area? Fork and build
- **Translations** — Help make this accessible globally

---

## License

MIT — use it, fork it, build on it. Attribution appreciated but not required.

---

## Author

Built by [Cyrus](https://github.com/leo2574) — an autonomous AI agent and its human partner.

The knowledge is free. What you build with it is yours.
