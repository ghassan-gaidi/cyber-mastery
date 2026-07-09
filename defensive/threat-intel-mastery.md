# Threat Intelligence, Hunting, and Adversary Tracking — Mastery Synthesis

> Comprehensive synthesis of 40 cybersecurity skills covering threat intelligence lifecycle, MITRE ATT&CK, IOC management, STIX/TAXII, threat hunting, adversary profiling, MISP, dark web monitoring, CTI reporting, and hypothesis-driven hunting.

---

## Table of Contents

1. [Threat Intelligence Lifecycle](#1-threat-intelligence-lifecycle)
2. [MITRE ATT&CK Framework Usage](#2-mitre-attack-framework-usage)
3. [IOC Management and Enrichment](#3-ioc-management-and-enrichment)
4. [STIX/TAXII Sharing](#4-stixtaxii-sharing)
5. [Threat Hunting Methodology](#5-threat-hunting-methodology)
6. [Adversary Profiling and Tracking](#6-adversary-profiling-and-tracking)
7. [MISP Deployment and Operations](#7-misp-deployment-and-operations)
8. [Dark Web Monitoring](#8-dark-web-monitoring)
9. [CTI Report Generation](#9-cti-report-generation)
10. [Threat Hunt Hypothesis Development](#10-threat-hunt-hypothesis-development)

---

## 1. Threat Intelligence Lifecycle

### 1.1 The Six-Phase Intelligence Cycle

The threat intelligence lifecycle is a structured, iterative process transforming raw data into actionable intelligence. Each phase builds on the previous, and feedback loops drive continuous improvement.

**Phase 1: Direction (Requirements Gathering)**
- Define Priority Intelligence Requirements (PIRs) that answer organizational questions
- PIR examples: "Which threat actors target our sector?", "What vulnerabilities are actively exploited?", "Are our credentials on the dark web?"
- Map PIRs to intelligence levels: **Strategic** (executive decisions), **Operational** (security operations), **Tactical** (immediate defense)
- Use ticketing systems (Jira, ServiceNow) to manage requirement tracking

**Phase 2: Collection (Data Acquisition)**
- Sources: OSINT (abuse.ch, AlienVault OTX, PhishTank), commercial feeds (Recorded Future, Mandiant Advantage, CrowdStrike), government (CISA AIS, FBI InfraGard), ISACs (FS-ISAC, H-ISAC), internal telemetry
- Collection Management Framework maps requirements to sources, tracks gaps, ensures coverage
- CISA KEV catalog: automatically collect known exploited vulnerabilities
- Abuse.ch MalwareBazaar: recent malware samples with tags and signatures

**Phase 3: Processing (Normalization and Deduplication)**
- Normalize heterogeneous IOC formats into unified schema (STIX 2.1)
- Deduplicate using composite keys (type + value + source hash)
- Apply confidence scoring based on source fidelity
- Enrich with contextual data (WHOIS, passive DNS, threat actor attribution)

**Phase 4: Analysis (Contextualization and Assessment)**
- Apply structured analytical techniques: Analysis of Competing Hypotheses (ACH), Diamond Model
- Answer PIRs with evidence-backed assessments
- Use confidence qualifiers: "assess with high confidence", "suggests" (low confidence)
- Produce intelligence at appropriate level for audience

**Phase 5: Dissemination (Distribution to Stakeholders)**
- TLP classification controls sharing scope (RED → named recipients; GREEN → community; WHITE → public)
- Multi-channel delivery: executive briefings, SOC dashboards, automated IOC push to SIEM/firewall
- Ensure classification is applied consistently across all products

**Phase 6: Feedback (Evaluation and Refinement)**
- Collect stakeholder ratings (1-5 scale) on intelligence products
- Track metrics: products distributed, distribution by channel, analyst action rates
- Identify intelligence gaps where collection is insufficient
- Feed lessons back into requirements and collection planning

### 1.2 Intelligence Levels

| Level | Audience | Content | Frequency |
|-------|----------|---------|-----------|
| **Strategic** | C-suite, Board | Threat landscape trends, risk to business, geopolitical context | Monthly/Quarterly |
| **Operational** | CISO, IR leads | Active campaigns, adversary TTPs, defensive recommendations | Weekly |
| **Tactical** | SOC analysts, hunters | Specific IOCs, YARA rules, Sigma detections, CVEs | Daily/As-needed |
| **Flash** | All stakeholders | Urgent threat notification, immediate risk, actions | As-needed (within 2 hours) |

### 1.3 Quality Metrics

- **Hit Rate**: % of deployed IOCs generating true positive alerts
- **False Positive Rate**: % of IOC alerts that are benign
- **Coverage**: % of known threat techniques with IOC coverage
- **Freshness**: Average age of active indicators in database
- **Enrichment Latency**: Time from alert trigger to enriched output (target: <30 seconds)
- **API Success Rate**: >99% for enrichment services

---

## 2. MITRE ATT&CK Framework Usage

### 2.1 Framework Structure

MITRE ATT&CK organizes adversary behavior into:
- **14 Tactics** (the "why"): Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact, plus Reconnaissance and Resource Development
- **200+ Techniques** (the "how"): Specific methods like T1059 (Command and Scripting Interpreter)
- **Sub-techniques**: Granular variants (T1059.001 = PowerShell, T1059.003 = Windows Command Shell)
- **Data Sources**: Telemetry required to detect each technique (Process Creation, Network Traffic, etc.)

### 2.2 Programmatic Querying

```python
from attackcti import attack_client
lift = attack_client()

# Get all Enterprise techniques
enterprise_techniques = lift.get_enterprise_techniques()

# Get techniques used by a specific group
apt29_techniques = lift.get_techniques_used_by_group("G0016")

# Map group to technique details
for tech in apt29_techniques:
    tech_id = tech.get("external_references", [{}])[0].get("external_id", "")
    tactics = [p.get("phase_name", "") for p in tech.get("kill_chain_phases", [])]
```

### 2.3 ATT&CK Navigator

The Navigator creates custom visualizations via JSON layer files:
- **Score**: 0-100 representing detection completeness per technique
- **Color coding**: Red = no detection, Yellow = partial, Green = excellent
- **Multi-layer overlay**: Compare threat actor TTPs against detection coverage
- **Platform filtering**: Windows, Linux, macOS, Cloud, Azure AD, Office 365

### 2.4 Detection Gap Analysis

```
Coverage Score = Data_Source (0-25) + Rule_Quality (0-25) + Validation (0-25) + Enrichment (0-25)
```

| Score | Meaning | Criteria |
|-------|---------|----------|
| 0 | Blind | No rules, missing data sources |
| 25 | Minimal | Rule exists but not validated |
| 50 | Partial | Rule works but limited coverage |
| 75 | Good | Validated rule with good data sources |
| 100 | Excellent | Multiple validated rules, tested with emulation |

### 2.5 Cross-Group Comparison

Compare techniques across multiple threat groups to identify:
- **Common techniques**: Worth prioritizing for detection (shared by multiple adversaries)
- **Unique techniques**: Group-specific indicators for attribution
- **Coverage gaps**: Techniques used by high-priority actors where you have no detection

### 2.6 ATT&CK Coverage Mapping Roadmap

**Quarter 1**: Close critical gaps (Score 0, high prevalence techniques)
- Enable missing data sources
- Build and test rules for top 5 gap techniques
- Validate with adversary emulation (Atomic Red Team)

**Quarter 2**: Improve partial coverage (Score 25-50)
- Upgrade existing rules with enrichment
- Add secondary detection methods

**Quarter 3**: Mature good coverage (Score 50-75)
- Add behavioral analytics
- Implement detection-as-code pipeline

**Quarter 4**: Excellence (Score 75-100)
- Continuous testing with BAS tools
- Automated coverage regression testing

---

## 3. IOC Management and Enrichment

### 3.1 IOC Lifecycle State Machine

```
DISCOVERED → VALIDATED → ENRICHED → DEPLOYED → MONITORING → UNDER_REVIEW → RETIRED
```

**Confidence Decay**: Indicator confidence decreases over time as adversaries rotate infrastructure:
- IP addresses: 30-day half-life, retire after 90 days
- Domains: 90-day half-life, retire after 180 days
- File hashes: 365-day half-life, retire after 730 days
- URLs: 60-day half-life, retire after 120 days

### 3.2 Multi-Source Enrichment Engine

Build a unified enrichment pipeline orchestrating:

| Source | Purpose | Rate Limit |
|--------|---------|------------|
| **VirusTotal** | Multi-engine malware analysis (70+ AV engines) | Free: 4 req/min |
| **AbuseIPDB** | IP reputation with abuse confidence scoring | 1000/day |
| **Shodan** | Internet-wide scanner for ports, banners, vulns | 1 req/sec |
| **GreyNoise** | Distinguish targeted attacks from opportunistic scanning | Varies |
| **URLScan.io** | URL analysis with screenshots, DOM, network requests | Varies |

**Composite Risk Score Calculation**:
```python
score = (vt_malicious / total_engines) * 60 + (abuse_confidence / 100) * 40
# Malicious: ≥70, Suspicious: 40-69, Low Risk: 10-39, Clean: <10
```

### 3.3 Defanging and Sharing Pipeline

**Defanging standards**:
- `http://` → `hxxp://`, `https://` → `hxxps://`
- Dots in domains/IPs → `[.]`
- `@` in emails → `[@]`

**Pipeline flow**:
1. Extract IOCs from text (regex patterns for IPv4, domain, URL, email, hashes)
2. Normalize (lowercase, remove trailing slashes, URL-decode)
3. Deduplicate (SHA-256 of type:value:source)
4. Defang for human consumption
5. Convert to STIX 2.1 for machine consumption
6. Distribute via MISP, TAXII, or email reports

### 3.4 Indicator Quality Framework

- **Hit Rate**: Track percentage of deployed IOCs generating true positive alerts
- **False Positive Rate**: Monitor analyst overrides of automated confidence scores
- **Coverage**: Percentage of known threat techniques with IOC coverage
- **Freshness**: Average age of active indicators — flag stale IOCs

### 3.5 Splunk Threat Intelligence Integration

- **KV Store Collections**: ip_threat_intel, domain_threat_intel, file_hash_intel
- **Modular Inputs**: Automated feed collection (OTX, TAXII, CSV)
- **Correlation Searches**: Match events against IOC lookups in real-time
- **Threat Intelligence Framework**: Normalized IOC storage with automated enrichment

---

## 4. STIX/TAXII Sharing

### 4.1 STIX 2.1 Object Model

**SDOs (STIX Domain Objects)**:
- `indicator`: Detection pattern (IP, domain, hash, URL)
- `malware`: Malware family description
- `threat-actor`: Adversary group description
- `campaign`: Named set of adversary activity
- `attack-pattern`: MITRE ATT&CK technique reference
- `relationship`: Links between objects (uses, indicates, attributed-to)

**SCOs (STIX Cyber Observables)**: ipv4-addr, domain-name, url, file, email-addr, network-traffic

**SROs (STIX Relationship Objects)**: Relationship, Sighting

**Pattern Language Examples**:
```
[ipv4-addr:value = '203.0.113.1']
[domain-name:value = 'malicious.example.com']
[file:hashes.'SHA-256' = 'abc123...']
[url:value = 'http://evil.com/payload']
[process:command_line MATCHES 'powershell.*-enc.*' AND process:parent_ref.name = 'winword.exe']
```

### 4.2 TAXII 2.1 Architecture

Three service types:
1. **Discovery**: Returns available API roots
2. **API Root**: Contains collections, serves as interaction point
3. **Collection**: Logical grouping of STIX objects (GET/POST)

**Sharing Models**:
- **Hub-and-spoke**: Central server distributes to consumers
- **Peer-to-peer**: Bidirectional sharing between partners
- **Source-subscriber**: Producer publishes, consumers subscribe

### 4.3 Implementation Stack

```python
# Consumer
from taxii2client.v21 import Server, Collection, as_pages

server = Server("https://cti-taxii.mitre.org/taxii2/", user="", password="")
collection = Collection(f"{server.api_roots[0].url}collections/{COLLECTION_ID}/")

# Fetch objects with pagination
for envelope in as_pages(collection.get_objects, per_request=50):
    objects = envelope.get("objects", [])

# Producer (via Medallion or OpenTAXII)
collection.add_objects(stix_bundle.serialize())
```

### 4.4 TLP Enforcement

Automated pipelines must filter marking definitions before routing:
- `tlp-red`: Named recipients only, no shared platforms
- `tlp-amber`: Organization + trusted partners
- `tlp-green`: Community-wide (ISAC members)
- `tlp-white`: Public distribution

### 4.5 Key Pitfalls

- **Ignoring `spec_version`**: STIX 2.0 and 2.1 have incompatible schemas
- **No pagination handling**: TAXII servers cap at 100-1000 objects/request
- **Clock skew on `added_after`**: Use UTC exclusively, add 5-minute overlap windows
- **Storing raw STIX blobs**: Parse into relational/graph database for querying
- **Sharing TLP:RED inadvertently**: Filter marking definitions before routing to shared platforms

---

## 5. Threat Hunting Methodology

### 5.1 Hunting Philosophy

Threat hunting is **proactive, hypothesis-driven** security monitoring that assumes breach and searches for adversary activity that evaded automated detection. It complements (not replaces) automated detection.

### 5.2 Hunt Lifecycle

1. **Formulate Hypothesis**: Define testable hypothesis based on threat intelligence or ATT&CK gap analysis
2. **Identify Data Sources**: Determine which logs/telemetry validate or refute the hypothesis
3. **Execute Queries**: Run detection queries against SIEM and EDR platforms
4. **Analyze Results**: Examine for anomalies, correlating across multiple data sources
5. **Validate Findings**: Distinguish true positives from false positives
6. **Correlate Activity**: Link findings to broader attack chains and threat actor TTPs
7. **Document and Report**: Record findings, update detection rules, recommend response actions

### 5.3 Beaconing Detection (C2 Hunting)

**Frequency Analysis Approach**:
- Calculate connection intervals for each source-destination pair
- Compute mean interval, standard deviation, and coefficient of variation (CV)
- **CV < 0.20** indicates strong periodicity (likely beaconing)
- Minimum 50 connections over 24 hours
- Average interval between 30 seconds and 24 hours

**Splunk Beacon Detection Query**:
```spl
index=proxy OR index=firewall
| bin _time span=1s
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg_interval stdev(interval) as stdev_interval by src_ip dest
| where count > 50
| eval cv=stdev_interval/avg_interval
| where cv < 0.20 AND avg_interval > 30 AND avg_interval < 86400
```

**Cobalt Strike Detection Signatures**:
- Default TLS certificate serial: `8BB00EE`
- JA3/JA3S fingerprints for default Beacon profiles
- Named pipe patterns: `\\.\pipe\msagent_*`
- HTTP malleable profile patterns in request/response

### 5.4 YARA Rule Hunting

**Rule Authoring Best Practices**:
```yara
rule Malware_Detection {
    meta:
        description = "Detects specific malware family"
        severity = "critical"
    strings:
        $suspicious_string = "pattern" ascii
        $hex_pattern = { AA BB CC DD }
        $regex_pattern = /pattern[0-9]{4}/i
    condition:
        $mz at 0 and filesize < 2MB and (2 of ($suspicious*))
}
```

**Scanning Pipeline**:
- Compile rules from .yar files with namespace separation
- Scan filesystems, quarantine directories, memory dumps
- Use `yarGen` for automated rule generation from malware samples
- Integrate community rule sets (Florian Roth's signature-base)
- Build continuous hunting pipeline with filesystem monitoring (watchdog)

### 5.5 Data Exfiltration Detection

**Channels to Monitor**:
- HTTP/S uploads to unusual destinations
- DNS tunneling (high-entropy subdomains, frequent TXT queries)
- Cloud storage uploads (personal Google Drive, Dropbox)
- Email attachments to personal accounts
- Staging and compression before slow exfiltration

**Key ATT&CK Techniques**:
- T1041: Exfiltration Over C2 Channel
- T1048: Exfiltration Over Alternative Protocol
- T1567.002: Exfiltration to Cloud Storage
- T1029: Scheduled Transfer

### 5.6 Web Shell Detection

**Hypothesis**: "Adversary has deployed web shells on internet-facing servers for persistent access."

**Data Sources**:
- Sysmon Event ID 11 (File Creation) in web directories
- Web server process spawning cmd.exe, powershell.exe
- Anomalous HTTP POST requests to .aspx/.php/.jsp files
- File integrity monitoring on web content directories

### 5.7 Supply Chain Compromise Hunting

**Hypothesis**: "A software update mechanism has been compromised to deliver malicious payloads."

**Detection Approach**:
- Monitor for unusual child processes from update mechanisms
- Verify code signing certificates of update binaries
- Compare file hashes against known-good baselines
- Analyze network connections from update processes to unusual destinations
- Check for unauthorized modifications to build server artifacts

---

## 6. Adversary Profiling and Tracking

### 6.1 Profile Components

A complete threat actor profile includes:

| Component | Description |
|-----------|-------------|
| **Identity** | ATT&CK Group ID, aliases across vendors, suspected nation-state sponsor |
| **Motivations** | Espionage, financial gain, disruption, IP theft, hacktivism |
| **Targeting** | Sectors, geographies, organization sizes, technology targets |
| **Capabilities** | Custom malware, 0-day exploitation, supply chain capability |
| **Campaign History** | Notable operations with dates and impact |
| **TTPs** | Top 5 techniques per ATT&CK tactic phase |
| **Toolset** | Malware families, exploitation frameworks, living-off-the-land binaries |
| **Infrastructure** | C2 patterns, hosting preferences, domain registration patterns |

### 6.2 OSINT Collection Pipeline

**Sources**:
- Vendor reports (Mandiant, CrowdStrike, Recorded Future, Talos)
- Government advisories (CISA, NSA, FBI joint advisories)
- Malware repositories (VirusTotal, MalwareBazaar, Malpedia)
- Paste sites (Pastebin, GitHub Gists)
- Dark web forums
- Certificate transparency logs
- Social media and code repositories

**Tools**:
- **SpiderFoot**: Automated OSINT reconnaissance
- **Maltego**: Link analysis and visualization
- **Shodan**: Infrastructure discovery
- **AlienVault OTX**: Pulse-based threat intelligence
- **VirusTotal**: Malware sample correlation

### 6.3 Infrastructure Tracking

**Pivoting Techniques**:
- Passive DNS: Find historical domain-to-IP mappings
- Certificate Transparency: Discover new certificates for suspicious domains
- WHOIS: Find related registrations from same registrant
- SSL/TLS certificates: Find shared certificates across infrastructure
- JARM/JA3S fingerprints: Identify C2 framework signatures
- HTTP response fingerprints: Server banners, custom headers, favicon hashes

**C2 Framework Detection**:
```python
c2_queries = {
    "cobalt-strike": 'product:"Cobalt Strike Beacon"',
    "sliver": 'ssl.cert.subject.cn:"multiplayer" ssl.cert.issuer.cn:"operators"',
    "havoc": 'http.html_hash:-1472705893',
}
```

### 6.4 Structured Analytical Techniques

- **Diamond Model**: Adversary, Infrastructure, Capability, Victim — maps relationships between threat components
- **Analysis of Competing Hypotheses (ACH)**: Systematic evaluation of attribution hypotheses with evidence scoring
- **MITRE ATT&CK Mapping**: Document TTPs with technique IDs and procedure examples

### 6.5 Profile Distribution

- **Executive summary** (1 page): Who, motivation, recent campaigns, top risk, recommended actions
- **SOC analyst brief** (3-5 pages): Full TTP list with detection status, IOC list, hunt hypotheses
- **Technical appendix**: YARA rules, Sigma detections, STIX JSON for TIP import
- **Classification**: TLP:AMBER for internal; seek ISAC approval before external sharing

### 6.6 Common Pitfalls

- **IOC-centric profiles**: Building around IPs/domains rather than TTPs — profiles become stale within weeks
- **Vendor alias confusion**: Conflating groups due to shared malware/infrastructure
- **Binary attribution**: Treating attribution as certain when probabilistic — always qualify confidence
- **Neglecting criminal groups**: Overemphasis on nation-states while ignoring ransomware (higher probability threats)
- **Profile staleness**: TTPs evolve — profiles not updated quarterly miss technique changes

---

## 7. MISP Deployment and Operations

### 7.1 Architecture

MISP operates on an event-based model:
- **Events**: Containers for threat intelligence
- **Attributes**: Individual IOCs (IP, domain, hash, URL)
- **Objects**: Structured groupings of related attributes
- **Galaxies**: Threat actor profiles, malware families, attack patterns
- **Tags**: MITRE ATT&CK, TLP marking, sector tags

### 7.2 Docker Deployment

```yaml
services:
  misp:
    image: coolacid/misp-docker:core-latest
    ports: ["443:443", "80:80"]
    environment:
      - MYSQL_HOST=misp-db
      - MISP_ADMIN_EMAIL=admin@org.com
      - MISP_BASEURL=https://misp.org.com
  misp-db:
    image: mysql:8.0
  misp-redis:
    image: redis:7
```

### 7.3 Feed Configuration (PyMISP)

```python
from pymisp import PyMISP

misp = PyMISP('https://misp.local', 'API_KEY', ssl=False)

# Enable default OSINT feeds
misp.enable_feed(feed_id=1)  # CIRCL OSINT
misp.fetch_feed(feed_id=1)

# Add custom feed
from pymisp import MISPFeed
feed = MISPFeed()
feed.name = "Abuse.ch URLhaus"
feed.url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
feed.source_format = "csv"
misp.add_feed(feed)
```

### 7.4 Default OSINT Feeds

- CIRCL OSINT Feed
- Botvrij.eu Indicators of Compromise
- abuse.ch URLhaus
- abuse.ch Feodo Tracker (C2 IPs)
- abuse.ch SSL Blacklist
- MalwareBazaar Recent
- CyberCure IP Feed

### 7.5 SIEM Integration

**Splunk HEC Export**:
```python
headers = {"Authorization": f"Splunk {hec_token}"}
event = {
    "event": {"ioc_type": attr["type"], "ioc_value": attr["value"]},
    "sourcetype": "misp:attribute",
    "index": "threat_intel"
}
requests.post(f"{splunk_url}/services/collector/event", headers=headers, json=event)
```

### 7.6 Threat Landscape Analysis

Using PyMISP to generate landscape reports:
- Pull event statistics by threat level and date range
- Analyze attribute type distributions (IP, domain, hash, URL)
- Identify top MITRE ATT&CK techniques from event tags
- Track threat actor activity via galaxy clusters
- Generate temporal trend analysis of IOC submissions

---

## 8. Dark Web Monitoring

### 8.1 Monitoring Sources

| Source Type | Examples | Access Method |
|-------------|----------|---------------|
| **Dark Web Forums** | XSS, Exploit.in, BreachForums | Commercial services (Flashpoint, Intel 471) |
| **Ransomware Leak Sites** | LockBit, Cl0p, RansomHub | Automated monitoring via Recorded Future |
| **Paste Sites** | Pastebin, Ghostbin | Scraping API (Pastebin PRO $49.95/mo) |
| **Telegram Channels** | Criminal groups, data sellers | Commercial monitoring services |
| **Code Repositories** | GitHub Gists | GitHub API search |

### 8.2 Paste Site Monitoring

**Pastebin Scraping API**:
```python
class PastebinMonitor:
    def fetch_recent_pastes(self, limit=100):
        resp = requests.get("https://scrape.pastebin.com/api_scraping.php",
                           params={"limit": limit})
        return resp.json()

    def analyze_paste(self, content):
        findings = {"keyword_matches": [], "credential_matches": {}}
        # Check organization keywords
        for keyword in self.keywords:
            if keyword in content.lower():
                findings["keyword_matches"].append(keyword)
        # Check credential patterns (AWS keys, GitHub tokens, private keys, JWT)
        for pattern_name, pattern in self.credential_patterns.items():
            matches = pattern.findall(content)
            if matches:
                findings["credential_matches"][pattern_name] = matches
        return findings
```

**Credential Patterns to Monitor**:
- Email:password combinations
- AWS access keys (`AKIA[0-9A-Z]{16}`)
- GitHub tokens (`ghp_[0-9a-zA-Z]{36}`)
- Slack tokens (`xox[baprs]-[0-9a-zA-Z-]+`)
- Private keys (`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`)
- JWT tokens (`eyJ...`)
- Database connection strings

### 8.3 Ransomware Leak Site Investigation

When a claim appears about your organization:
1. Capture evidence via commercial service (do not access directly)
2. Assess legitimacy: Does claimed data align with known internal systems?
3. Check timestamp: Is this claim recent or historical?
4. Cross-reference with known security incidents
5. Engage IR team if claim appears credible

### 8.4 Operational Security (OPSEC)

**Critical Requirements**:
- Use dedicated physical machine or air-gapped VM (Whonix + VirtualBox)
- Connect via Tor Browser only — never standard browser
- Use cover identity with no links to organization
- Never log in with real credentials
- Document all sessions with timestamps
- Passive monitoring is generally lawful; active participation in criminal markets is not

### 8.5 Key Pitfalls

- **Direct access without OPSEC**: Exposes analyst IP, browser fingerprint, organization affiliation
- **Overreacting to unverified claims**: Ransomware groups fabricate claims for extortion
- **Missing clearnet sources**: Telegram, Discord, paste sites host significant criminal activity
- **No evidence preservation**: Dark web content disappears rapidly — capture immediately

---

## 9. CTI Report Generation

### 9.1 Report Types

| Type | Audience | Format | Frequency |
|------|----------|--------|-----------|
| **Strategic** | C-suite, Board | 1-3 pages, minimal jargon, business impact | Monthly/Quarterly |
| **Operational** | CISO, IR leads | 3-8 pages, moderate technical detail | Weekly |
| **Tactical** | SOC analysts, hunters | Structured tables, code blocks, 1-2 pages | Daily/As-needed |
| **Flash** | All stakeholders | 1 page max, within 2 hours of threat ID | As-needed |

### 9.2 Intelligence Writing Standards

**Key Judgments**: Lead with the most important finding in plain language.
- ❌ "This report examines threat actor TTPs associated with Cl0p ransomware"
- ✅ "Cl0p ransomware group is actively exploiting CVE-2024-20353 in Cisco ASA devices; organizations using unpatched ASA appliances face imminent ransomware risk"

**Confidence Qualifiers** (DNI ICD 203):
- **High confidence**: "assess with high confidence" — strong evidence, few assumptions
- **Medium confidence**: "assess" — credible sources but analytical assumptions required
- **Low confidence**: "suggests" — limited sources, significant uncertainty

### 9.3 Report Structure

1. **Executive Summary** (3-5 bullet points): Key findings, immediate business risk, top recommended action
2. **Threat Overview**: Who is the adversary? What is their objective? Why does this matter?
3. **Technical Analysis**: TTPs with ATT&CK technique IDs, IOCs, observed campaign behavior
4. **Impact Assessment**: Potential operational, financial, reputational impact
5. **Recommended Actions**: Prioritized, time-bound defensive measures with owner assignment
6. **Appendices**: Full IOC lists, YARA rules, Sigma detections, raw source references

### 9.4 TLP and Distribution

- **TLP:RED**: Named recipients only; cannot be shared outside briefing room
- **TLP:AMBER+STRICT**: Organization only; no sharing with subsidiaries/partners
- **TLP:AMBER**: Organization + trusted partners with need-to-know
- **TLP:GREEN**: Community-wide (ISAC members, sector peers)
- **TLP:WHITE/CLEAR**: Public distribution; no restrictions

Include TLP watermark on every page header and footer.

### 9.5 Quality Control Checklist

Before dissemination:
- **Accuracy**: All facts sourced and cited; no unsubstantiated claims
- **Clarity**: Target audience can understand without additional context
- **Actionability**: Every section drives a decision or action
- **Classification**: TLP correctly applied; no source identification in AMBER/RED
- **Timeliness**: Intelligence still current (events >48 hours need freshness assessment)

### 9.6 Common Pitfalls

- **Writing for analysts instead of audience**: Technical detail appropriate for SOC overwhelms executives
- **Omitting confidence levels**: Statements without qualifiers appear as established facts
- **Intelligence without recommendations**: Describes threats without prescribing actions
- **Stale intelligence**: Publishing on resolved threats creates alarm without utility
- **Over-classification**: Applying TLP:RED to shareable information impedes community sharing

---

## 10. Threat Hunt Hypothesis Development

### 10.1 Hypothesis Sources

| Source | Example Hypothesis |
|--------|-------------------|
| **APT Campaign Report** | "APT29 has been observed using T1059.001 (PowerShell) for execution — are we seeing similar patterns?" |
| **ATT&CK Gap Analysis** | "We have no detection for T1055 (Process Injection) — adversary may be using it undetected" |
| **UEBA Alert** | "User account showing anomalous login patterns — possible credential compromise" |
| **Sector Threat Intel** | "Ransomware groups targeting healthcare are using Cobalt Strike — hunt for beaconing" |

### 10.2 Hypothesis Structure

```
Hunt ID: TH-[TYPE]-[DATE]-[SEQ]
Technique: TA0001 / T1059.001
Hypothesis: [Testable statement]
Data Sources: [Required logs/telemetry]
Query: [Detection query]
Expected Results: [What would confirm/refute]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```

### 10.3 Hunt Categories

**Intelligence-Driven Hunts**:
- Based on specific APT campaign reports
- Map adversary TTPs to your environment
- Search for known IOCs and behavioral patterns

**Gap-Driven Hunts**:
- Based on ATT&CK coverage gap analysis
- Focus on techniques with no detection
- Validate that blind spots are not being exploited

**Anomaly-Driven Hunts**:
- Based on UEBA alerts or statistical anomalies
- Investigate deviations from baseline behavior
- Correlate across multiple data sources

**Situational Awareness Hunts**:
- Based on industry sector threats
- Proactive search for emerging attack patterns
- Validate security posture against current threat landscape

### 10.4 Data Source Requirements

| Hunt Type | Required Data Sources |
|-----------|----------------------|
| **Beaconing** | Proxy/firewall logs, DNS queries, Zeek conn.log |
| **Process Injection** | Sysmon EventCode 8/10, EDR process telemetry |
| **Credential Dumping** | LSASS access events, Sysmon EventCode 10 |
| **Lateral Movement** | Windows Security 4624/4625, SMB traffic logs |
| **Web Shell** | File creation in web dirs, web server process spawning |
| **Data Exfiltration** | DLP/CASB logs, DNS tunneling analysis, data volume anomalies |

### 10.5 Hypothesis Validation Framework

1. **Define success criteria**: What specific evidence would confirm the hypothesis?
2. **Define refutation criteria**: What would prove the hypothesis wrong?
3. **Execute queries**: Run detection queries across SIEM and EDR
4. **Analyze results**: Look for patterns, not just individual events
5. **Correlate**: Link findings to broader attack chains
6. **Validate**: Confirm true positives through contextual analysis
7. **Document**: Record findings, update detection rules, recommend actions

### 10.6 Common Hunt Scenarios

**Scenario 1: Cobalt Strike in the Network**
- Hypothesis: "Compromised endpoint is beaconing to Cobalt Strike C2 server"
- Data: Proxy logs, TLS certificates, JA3 fingerprints
- Detection: CV < 0.20, default cert serial 8BB00EE, named pipe patterns

**Scenario 2: Credential Dumping**
- Hypothesis: "Adversary has dumped credentials from LSASS memory"
- Data: Sysmon EventCode 10 (ProcessAccess), EDR process telemetry
- Detection: Access to lsass.exe from unusual processes, Mimikatz patterns

**Scenario 3: Supply Chain Compromise**
- Hypothesis: "A software update mechanism has been compromised"
- Data: Process creation from update mechanisms, code signing verification
- Detection: Unusual child processes, hash mismatches, unauthorized network connections

**Scenario 4: DNS Tunneling**
- Hypothesis: "Malware is using DNS for C2 communication"
- Data: DNS query logs, subdomain entropy analysis
- Detection: High-entropy subdomains, unusual TXT query volume, query length anomalies

---

## Appendix: Key Tools and Libraries

### Python Libraries

| Library | Purpose |
|---------|---------|
| `attackcti` | Query ATT&CK STIX data via TAXII |
| `mitreattack-python` | Programmatic access to ATT&CK data |
| `stix2` | Create, parse, validate STIX 2.1 objects |
| `taxii2-client` | TAXII 2.0/2.1 client operations |
| `pymisp` | Python API for MISP |
| `pycti` | Python API for OpenCTI |
| `yara-python` | YARA rule scanning |
| `shodan` | Shodan API integration |
| `vt-py` | VirusTotal API client |

### Platforms

| Platform | Purpose |
|----------|---------|
| **MISP** | Open-source TIP for IOC management and sharing |
| **OpenCTI** | Graph-based CTI platform with ATT&CK integration |
| **TheHive** | Incident response case management |
| **Cortex** | Automated IOC enrichment |
| **ATT&CK Navigator** | Coverage heatmap visualization |
| **RITA** | Automated beacon detection in Zeek logs |
| **yarGen** | Automated YARA rule generation |

### Detection Rule Formats

| Format | Platform | ATT&CK Support |
|--------|----------|----------------|
| **Sigma** | Cross-platform (Splunk, Sentinel, Elastic, QRadar) | Native ATT&CK tagging |
| **YARA** | File/memory scanning | Referenced in meta field |
| **Splunk SPL** | Splunk ES | ATT&CK annotations |
| **KQL** | Microsoft Sentinel/Defender | ATT&CK mapping |
| **EQL** | Elastic Security | ATT&CK tagging |

---

## Appendix: NIST CSF Alignment

All skills in this synthesis align to NIST Cybersecurity Framework functions:

- **ID.RA-01**: Risk assessment — threat intelligence identification
- **ID.RA-05**: Risk determination — threat intelligence analysis
- **DE.CM-01**: Continuous monitoring — detection rule deployment
- **DE.AE-02**: Anomaly analysis — behavioral analytics and hunting
- **DE.AE-07**: Event analysis — threat hunt investigation
- **RS.MA-01**: Incident management — response to detected threats

---

*Synthesis generated from 40 Anthropic Cybersecurity Skills. Each skill represents practical, field-tested methodology for threat intelligence operations.*
