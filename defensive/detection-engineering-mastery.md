# Detection Engineering, SIEM & Security Monitoring — Master Reference

> Synthesized from 19 cybersecurity skills covering Splunk SPL, Sigma, SIEM use cases, false positive reduction, endpoint detection, cloud SIEM, network IDS/IPS, eBPF security, purple team operations, and SOC dashboards.

---

## 1. SIEM Rule Development (Splunk SPL & Sigma)

### Splunk SPL Detection Patterns

**Threshold-Based Detection** — Detects events exceeding count within time window:
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| stats count as failed_logins dc(TargetUserName) as unique_users by src_ip
| where failed_logins > 10 AND unique_users > 3
| eval severity="high"
```

**Sequence-Based Detection** — Correlates failed→success login chains:
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval login_status=case(EventCode=4625, "failure", EventCode=4624, "success")
| stats count(eval(login_status="failure")) as failures count(eval(login_status="success")) as successes
  latest(_time) as last_event by src_ip, TargetUserName
| where failures > 5 AND successes > 0
```

**Anomaly Detection with Baseline** — Compares current activity against 7-day baseline:
```spl
| bin _time span=1h
| stats count as current_count by src_ip, _time
| join src_ip type=left [
    search earliest=-7d@d latest=-1d@d | stats avg(count) as avg_count stdev(count) as stdev_count by src_ip
]
| eval threshold=avg_count + (3 * stdev_count)
| where current_count > threshold
```

**Key SPL Commands for Detection Engineering:**
| Command | Purpose |
|---------|---------|
| `tstats` | High-performance queries against data models (10-100x faster than raw index) |
| `stats` / `eventstats` / `streamstats` | Aggregation, running statistics |
| `lookup` | Enrich with asset, identity, threat intel data |
| `where` | Threshold/filter conditions |
| `bin` | Time bucketing for windowed analysis |
| `dedup` / `mvexpand` | Deduplication or field expansion |
| `collect` | Write to summary index for baselines |

**Performance Optimization:**
- Use `tstats summariesonly=true` with data models (CIM-normalized)
- Limit time ranges with `earliest`/`latest`
- Use summary indexing for historical baselines
- Prefer indexed fields over raw field extraction

### Sigma Rules (Vendor-Agnostic Detection)

**Sigma Rule Structure (YAML):**
```yaml
title: Mimikatz Credential Dumping via LSASS Access
id: 0d894093-71bc-43c3-8d63-bf520e73a7c5
status: stable
level: high
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
    filter_main_svchost:
        SourceImage|endswith: '\svchost.exe'
    condition: selection and not 1 of filter_main_*
```

**Sigma Conversion Pipeline:**
```python
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

pipeline = splunk_windows_pipeline()
backend = SplunkBackend(pipeline)
rule = SigmaRule.from_yaml(open("rule.yml").read())
splunk_query = backend.convert_rule(rule)
```

**pySigma Backend Options:**
| Backend | Target Platform |
|---------|----------------|
| `pySigma-backend-splunk` | Splunk SPL |
| `pySigma-backend-elasticsearch` | Elastic Lucene/EQL |
| `pySigma-backend-microsoft365defender` | Microsoft Sentinel KQL |

**Key Sigma Concepts:**
- **Logsource**: Defines category (process_creation, network_connection) and product (windows, linux)
- **Pipeline**: Field mapping from generic Sigma fields → SIEM-specific fields
- **Backend**: Translates Sigma logic to target query language
- **Detection Logic**: `selection` (what to match) + `filter` (what to exclude) + `condition` (boolean logic)

---

## 2. Detection-as-Code

### Sigma as the Standard

Detection-as-code treats SIEM rules like software: version-controlled, tested, peer-reviewed, and deployed via CI/CD.

**CI/CD Pipeline Example (GitHub Actions):**
```yaml
name: Sigma Rule CI
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install pySigma pySigma-validators-sigmaHQ
      - run: sigma check rules/
      - run: sigma convert -t splunk -p splunk_windows rules/ > /dev/null
```

**Validation Script:**
```python
from sigma.rule import SigmaRule
from sigma.validators.core import SigmaValidator

rule = SigmaRule.from_yaml(open("rule.yml").read())
validator = SigmaValidator()
issues = validator.validate_rule(rule)
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

### ATT&CK Coverage Tracking

Generate ATT&CK Navigator layers from Sigma rules:
```python
layer = {"name": "SOC Detection Coverage", "techniques": []}
for root, dirs, files in os.walk("sigma/rules/"):
    for f in files:
        if f.endswith(".yml"):
            rule = SigmaRule.from_yaml(open(os.path.join(root, f)).read())
            for tag in rule.tags:
                if str(tag).startswith("attack.t"):
                    layer["techniques"].append({
                        "techniqueID": str(tag).replace("attack.", "").upper(),
                        "color": "#31a354", "score": 1
                    })
```

### Use Case Lifecycle Management

```
1. PROPOSED    → New detection need identified (threat intel, gap analysis, incident finding)
2. DEVELOPMENT → Query written, false positive analysis, tuning
3. TESTING     → Atomic Red Team validation, 7-day backtest
4. STAGING     → Deployed in alert-only mode (no incident creation) for 14 days
5. PRODUCTION  → Full production with incident creation and SOAR integration
6. REVIEW      → Quarterly review of effectiveness, false positive rate, relevance
7. DEPRECATED  → Technique no longer relevant or replaced by better detection
```

### Detection Coverage Gap Analysis

```python
# Map current rules to ATT&CK
covered = set()
for rule in current_rules:
    covered.update(rule["techniques"])

all_techniques = set()  # loaded from enterprise-attack.json
gaps = all_techniques - covered
print(f"Coverage: {len(covered)/len(all_techniques)*100:.1f}%")
```

**Industry Benchmark:** Enterprise SIEMs on average cover only **21% of MITRE ATT&CK techniques**.

---

## 3. Alert Fatigue Reduction

### The Problem
- Up to **45% of SIEM alerts are false positives**
- A typical SOC analyst can only investigate **20-25 alerts per shift**
- Alert fatigue leads to critical true positives being dismissed

### Risk-Based Alerting (RBA) — The Game Changer

Instead of alerting on every threshold breach, **contribute risk scores** and only alert when cumulative risk exceeds a threshold:

```spl
--- Risk contribution: Failed logins (no alert)
index=wineventlog EventCode=4625
| eval risk_score = case(count > 50, 40, count > 20, 25, count > 10, 15)
| eval risk_object = src_ip
| collect index=risk

--- Risk threshold alert: Only fires when cumulative risk ≥ 75
index=risk earliest=-24h
| stats sum(risk_score) AS total_risk by risk_object
| where total_risk >= 75
```

**Before vs After RBA:**
| Metric | Before | After |
|--------|--------|-------|
| Daily alerts | 1,847 | 287 |
| Alerts/analyst/shift | 154 | 24 |
| False positive rate | 82% | 23% |
| Signal-to-noise | 0.10 | 1.78 |

### False Positive Reduction Framework

**Step 1: Identify** (Weekly) — Pull top 10 rules by volume, calculate FP rate, flag rules with FP > 30%

**Step 2: Analyze** (Weekly) — Sample 20 false positives per rule, categorize root cause

**Step 3: Tune** (Bi-weekly) — Adjust thresholds, add allowlists, enhance correlation, add enrichment

**Step 4: Validate** (Monthly) — Run Atomic Red Team tests, calculate new FP rate, document rationale

**Step 5: Report** (Quarterly) — FP reduction metrics, volume trends, analyst productivity improvements

### Tuning Techniques

| Technique | Example | Impact |
|-----------|---------|--------|
| **Threshold adjustment** | 5→20 failures, require 3+ accounts | Eliminates bulk of FPs |
| **Allowlist/Exclusion** | Whitelist known AV tools accessing LSASS | Removes known-benign |
| **Correlation enhancement** | Single-event → multi-signal (failed login + external conn) | Dramatically reduces noise |
| **Time-based exclusion** | Exclude Sunday 2-4am maintenance windows | Removes scheduled FPs |
| **Behavioral baseline** | User deviation > 3σ from their own baseline | Personalizes detection |
| **TI filtering** | Only alert when dest matches threat intel | Eliminates benign IPs |

### Alert Consolidation

Group related alerts from same source/campaign:
```spl
index=notable earliest=-1h
| dedup src, rule_name span=300
| stats count AS alert_count, values(rule_name) AS related_rules by src
| where alert_count > 3
```

### Tiered Alert Routing

| Tier | Criteria | Action |
|------|----------|--------|
| Tier 1 (Automated) | Risk < 30, known FP patterns, informational | Auto-close, dashboard only |
| Tier 2 (Analyst) | Risk 30-75, medium confidence | Standard triage queue |
| Tier 3 (Priority) | Risk > 75, deception alerts, known malware | Immediate investigation + auto-contain |

### Key Metrics

| Metric | Target |
|--------|--------|
| False Positive Rate | < 20% |
| Alert Volume Reduction | 30-50% per quarter |
| Mean Triage Time | < 8 minutes |
| Rule Precision | > 0.80 |
| Alerts/analyst/shift | 40-60 |

---

## 4. Log Source Management

### Centralized Logging Architecture

```
Endpoints → Fluent Bit (lightweight forwarder) → Fluentd (aggregator) → SIEM
                                    ↓
                              Elasticsearch / Splunk
```

### Fluent Bit → Fluentd Pipeline

**Fluent Bit** (endpoint agent):
```ini
[INPUT]
    Name tail
    Path /var/log/syslog
    Parser syslog

[FILTER]
    Name record_transformer
    Rename hostname source_host

[OUTPUT]
    Name forward
    Host fluentd-server
    Port 24224
```

**Fluentd** (central aggregator):
```xml
<source>
  @type forward
  port 24224
</source>

<filter **>
  @type record_transformer
  <record>
    datacenter "#{ENV['DATACENTER']}"
  </record>
</filter>

<match **>
  @type elasticsearch
  host elasticsearch.internal
  port 9200
  index_name security-logs
</match>
```

### rsyslog Centralization with TLS

**Server Configuration:**
```
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1"
       StreamDriver.Authmode="x509/name")
input(type="imtcp" port="6514")
template(name="PerHostLog" type="string"
         string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
```

**Client Configuration (Reliable Forwarding):**
```
action(type="omfwd" target="10.0.0.1" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       queue.type="LinkedList" queue.filename="fwdRule1"
       queue.maxdiskspace="1g" queue.saveonshutdown="on"
       action.resumeRetryCount="-1")
```

### File Integrity Monitoring (AIDE)

Monitors `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/boot` for unauthorized changes via cryptographic checksums:
```bash
aide --init          # Create baseline
aide --check         # Compare current state vs baseline
```

### Log Source Priority Matrix

| Priority | Source Type | Log Events | SIEM Value |
|----------|------------|------------|------------|
| Critical | Windows Security | 4624/4625/4688/4698/4104 | Authentication, process, scheduled tasks |
| Critical | Sysmon | EventCode 1/3/7/8/10/11/13 | Process, network, file, registry, memory |
| High | Firewall | Allow/Deny, bytes transferred | Network flow, connections |
| High | Proxy | URL, user-agent, bytes | Web activity, C2 detection |
| High | DNS | Queries, responses | Domain resolution, tunneling |
| Medium | EDR | Process, file, network events | Endpoint behavior |
| Medium | VPN | Connect/disconnect, auth | Remote access |
| Lower | HTTP server | Access logs | Web application attacks |

---

## 5. Cloud SIEM (Microsoft Sentinel)

### KQL Detection Rules

**LSASS Memory Access (Credential Dumping):**
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "lsass.exe"
| where ActionType == "ProcessAccessed"
| where InitiatingProcessFileName !in ("svchost.exe", "csrss.exe", "MsMpEng.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
```

**Suspicious PowerShell:**
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "Invoke-Expression", "IEX",
    "DownloadString", "FromBase64String", "Net.WebClient")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Sentinel-Specific Features

| Feature | Description |
|---------|-------------|
| **Fusion ML Engine** | Multi-stage attack detection using ML correlation |
| **Anomaly Analytics** | Baseline-based anomaly detection per entity |
| **Threat Intelligence Matching** | Auto-correlate events against TI feeds |
| **Lighthouse** | Multi-tenant management for MSSPs |
| **Workbooks** | Built-in dashboard framework |

### Cloud SIEM Data Connectors

| Connector | Data Type | Detection Value |
|-----------|-----------|-----------------|
| Azure AD Sign-in Logs | Authentication events | Impossible travel, MFA bypass |
| Azure Activity | Control plane operations | Privilege escalation, resource tampering |
| Microsoft 365 Defender | Endpoint/Identity/Email | Cross-domain correlation |
| AWS CloudTrail | API calls | IAM abuse, data exfiltration |
| GCP Audit Logs | Admin/activity events | GCP-specific TTPs |

---

## 6. Endpoint Detection (EDR, osquery, Wazuh)

### CrowdStrike Falcon EDR Deployment

**Sensor Installation:**
```cmd
WindowsSensor_7.18.17106.exe /install /quiet /norestart CID=<YOUR_CID>
```

**Prevention Policy Configuration:**
```
Machine Learning:     Aggressive (Cloud), Moderate (Sensor)
Behavioral Protection: On Write: Enabled, Interpreter-Only: Enabled
Exploit Mitigation:   Memory scanning: Enabled, Code injection: Enabled
Ransomware:           Enabled, Shadow copy protection: Enabled
```

**SIEM Integration:** CrowdStrike Falcon Event Streams → Splunk (via Technical Add-on) or Elastic (via CrowdStrike module)

**Key EDR Concepts:**
| Term | Definition |
|------|-----------|
| **IOA (Indicators of Attack)** | Behavioral detections based on adversary techniques |
| **RTR (Real-Time Response)** | Remote shell through Falcon console |
| **Network Containment** | Isolate endpoint from network via EDR |
| **Sensor Grouping Tags** | Auto-assign hosts to policies |

### Osquery for Endpoint Monitoring

**SQL-Based Threat Hunting Queries:**
```sql
-- Fileless malware (processes without on-disk binary)
SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0;

-- Unauthorized SSH keys
SELECT * FROM authorized_keys WHERE NOT key LIKE '%admin-team%';

-- Processes connecting to external IPs
SELECT DISTINCT p.name, pn.remote_address, pn.remote_port
FROM process_open_sockets pn JOIN processes p ON pn.pid = p.pid
WHERE pn.remote_address NOT LIKE '10.%'
  AND pn.remote_address NOT LIKE '172.16.%'
  AND pn.remote_address NOT LIKE '192.168.%';

-- Unsigned executables (Windows)
SELECT p.name, a.result FROM processes p
JOIN authenticode a ON p.path = a.path WHERE a.result != 'trusted';
```

**FleetDM** provides centralized osquery fleet management with TLS enrollment and config distribution.

**Osquery Pitfalls:**
- Complex queries with large table scans impact endpoint performance
- Schedule intervals too aggressive (every 60s) cause CPU spikes
- Not using differential mode (logs all results vs. only changes)
- Missing event tables (process_events, socket_events require `--disable_events=false`)

### Wazuh SIEM/XDR

**Architecture:** Manager + Agent model with REST API

**Key Capabilities:**
- Custom decoders/rules in XML for organization-specific detections
- Logtest endpoint for validating decoder and rule logic
- Automated response actions (firewall blocking, process termination)
- Compliance monitoring (PCI DSS, HIPAA, GDPR)

---

## 7. Network IDS/IPS Tuning

### Snort 3 vs Suricata Comparison

| Feature | Snort 3 | Suricata 7 |
|---------|---------|------------|
| Architecture | Single/multi-threaded | Multi-threaded (AF_PACKET) |
| Config Format | Lua (snort.lua) | YAML (suricata.yaml) |
| Rule Management | PulledPork 3 | suricata-update |
| TLS Fingerprinting | Limited | JA3/JA3S native |
| SSH Fingerprinting | No | HASSH native |
| Log Format | Unified2, JSON | EVE JSON (structured) |
| Performance | Good for <5 Gbps | Excellent for 10+ Gbps |
| Community Rules | Snort Community | ET Open + ET Pro |

### Suricata Configuration Highlights

**AF_PACKET for High Performance:**
```yaml
af-packet:
  - interface: eth1
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    ring-size: 200000
    buffer-size: 262144
```

**EVE JSON Logging (structured output for SIEM):**
```yaml
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      community-id: true   # Enables cross-tool correlation
      types:
        - alert: { payload: yes, payload-printable: yes }
        - http: { extended: yes }
        - dns: { query: yes, answer: yes }
        - tls: { extended: yes }    # JA3 fingerprints
        - files: { force-hash: [md5, sha256] }
```

### Custom Detection Rules

**Snort Rule:**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (
    msg:"Possible Reverse Shell on port 4444";
    flow:established,to_server;
    content:"/bin/sh"; nocase;
    sid:1000001; rev:1; classtype:trojan-activity; priority:1;
)
```

**Suricata Rule (with JA3):**
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Cobalt Strike JA3 Hash";
    ja3.hash; content:"72a589da586844d7f0818ce684948eea";
    sid:9000003; rev:1; classtype:trojan-activity; priority:1;
)
```

### Tuning Best Practices

| Technique | Purpose |
|-----------|---------|
| `threshold` | Limit alert frequency (e.g., max 10 per src per minute) |
| `suppress` | Completely silence rules for known-benign sources |
| `disable.conf` | Disable overly broad rules entirely |
| `reputation lists` | Block/allow known-good/bad IPs at engine level |

### NIC Configuration (Critical!)
```bash
# MUST disable offloading before running IDS
sudo ethtool -K eth1 gro off lro off tso off gso off rx off tx off
sudo ip link set eth1 promisc on
```
**Pitfall:** Forgetting to disable NIC offloading causes missed packets due to checksum errors.

---

## 8. Purple Team Operations

### Purple Team Exercise Framework

**Exercise Definition:**
```yaml
exercise_id: PT-2024-Q1
duration: 8 hours
scope:
  environment: Production (Finance VLAN)
  systems_in_scope: [WORKSTATION-TEST01, DC-TEST]
objectives:
  - Validate 15 detection rules mapped to FIN7 TTPs
  - Test SOC analyst response to real attack indicators
  - Identify detection gaps for credential access and lateral movement
```

**ATT&CK-Mapped Test Matrix:**

| ATT&CK ID | Technique | Test Tool | Expected Detection |
|-----------|-----------|-----------|-------------------|
| T1059.001 | PowerShell | Atomic RT | PowerShell execution alert |
| T1053.005 | Scheduled Task | Atomic RT | Task creation alert |
| T1003.001 | LSASS Memory | Mimikatz | Credential dumping alert |
| T1550.002 | Pass-the-Hash | Mimikatz | NTLM anomaly |
| T1021.002 | SMB/PsExec | PsExec | Service creation alert |
| T1071.001 | Web C2 | Cobalt Strike | C2 beacon detection |
| T1490 | Inhibit Recovery | vssadmin | Shadow copy deletion |

**Execution with Logging:**
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
# Notify blue team, then check SIEM
Invoke-AtomicTest T1003.001 -TestNumbers 1
# Check for LSASS access alert
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

**Real-Time Blue Team Monitoring:**
```spl
index=notable earliest=-1h
| where Computer IN ("WORKSTATION-TEST01", "DC-TEST")
| eval detection_latency = _time - orig_time
| table _time, rule_name, urgency, src, dest, latency_seconds
```

### Collaborative Gap Remediation

When a gap is found during the exercise:
1. **Red Team**: Pauses, logs the undetected technique
2. **Blue Team**: Builds detection rule in real-time
3. **Re-test**: Red team re-executes the technique
4. **Confirm**: Alert fires → gap closed

### Purple Team Report Format

```
Techniques Tested:     15
Detected:              11 (73%)
Gaps Identified:       4 (27%)
Gaps Remediated Same Day: 3
Avg Detection Latency: 38 seconds
Post-Exercise Coverage: 93% (14/15)
```

---

## 9. SOC Dashboards

### Incident Response Dashboard Components

**1. Incident Summary Panel:**
```spl
| makeresults
| eval incident_id="IR-2024-0450", status="CONTAINMENT",
       severity="Critical", affected_hosts=7, contained_hosts=5,
       iocs_identified=23
```

**2. Affected Systems Panel:**
```spl
| inputlookup ir_affected_systems.csv
| eval status_color = case(
    status="Compromised", "#e74c3c",
    status="Contained", "#2ecc71",
    status="Investigating", "#f39c12")
| stats count by status
```

**3. IOC Tracking Panel:**
```spl
index=* (src_ip IN ("185.234.218.50") OR dest="evil-c2.com")
| timechart span=1h count by sourcetype
```

**4. Response Timeline Panel:**
```spl
| inputlookup ir_timeline.csv
| sort _time
| table _time, phase, action, analyst, details
```

### SOC Operations Metrics

```spl
--- MTTD (Mean Time to Detect)
index=notable earliest=-30d status_label="Resolved*"
| eval mttd_minutes = round((time_of_first_event - orig_time) / 60, 1)
| stats avg(mttd_minutes) AS avg_mttd, perc95(mttd_minutes) AS p95_mttd

--- MTTR (Mean Time to Respond)
| eval mttr_hours = round((status_end - _time) / 3600, 1)
| stats avg(mttr_hours) AS avg_mttr by urgency

--- Analyst Workload
index=notable earliest=-7d
| stats count by owner | sort - count

--- Alert Disposition
index=notable earliest=-30d status_label IN ("Resolved*", "Closed*")
| stats count by disposition
```

### Dashboard Tool Comparison

| Tool | Strengths | Best For |
|------|-----------|----------|
| Splunk Dashboard Studio | Drag-and-drop, real-time, ES integration | Enterprise SOC |
| Elastic Kibana | Lens, Maps, Canvas, ML integration | Elastic stack shops |
| Grafana | Multi-source, open-source, customizable | Mixed environments |
| Sentinel Workbooks | Azure-native, KQL-based | Microsoft-centric |

### Executive Briefing Dashboard

Non-technical panels showing:
- Business impact summary
- Containment progress bar
- MTTD/MTTR trends
- Incident volume comparison (month-over-month)
- Top threat categories

---

## 10. Atomic Red Team Testing

### Installation and Setup

```powershell
# Install execution framework
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
Install-Module -Name powershell-yaml -Scope CurrentUser -Force

# Download atomics library
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

### Execution with Logging

```powershell
function Invoke-AtomicWithLogging {
    param([string]$TechniqueId, [int[]]$TestNumbers)

    $result = @{ technique_id = $TechniqueId; start_time = (Get-Date).ToString("o") }

    foreach ($testNum in $TestNumbers) {
        Invoke-AtomicTest $TechniqueId -TestNumbers $testNum -Confirm:$false
        Start-Sleep -Seconds 30  # Wait for SIEM ingestion
    }

    $result | ConvertTo-Json | Set-Content "logs/${TechniqueId}_$(Get-Date -f yyyyMMdd_HHmmss).json"
}
```

### SIEM Validation Queries

**After executing T1003.001 (LSASS):**
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe" earliest=-1h
| stats count by Computer, SourceImage, GrantedAccess
```

**After executing T1547.001 (Registry Run Key):**
```spl
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*" earliest=-1h
| stats count by Computer, Image, TargetObject
```

**Hunt for Atomic Red Team artifacts:**
```spl
index=windows | search "*AtomicRedTeam*" OR "*Invoke-AtomicTest*"
| stats count by sourcetype, EventCode, host
```

### ATT&CK Coverage Gap Analysis

**Python Coverage Report Generator:**
```python
def generate_coverage_report(atomics_inventory, execution_logs, detection_results):
    report = {"tactics": {}, "gaps": []}

    for tactic, technique_ids in TACTIC_TECHNIQUE_MAP.items():
        for tech_id in technique_ids:
            executed = tech_id in execution_logs
            detected = detection_results.get(tech_id, {}).get("detected", False)

            if executed and not detected:
                report["gaps"].append({
                    "technique_id": tech_id,
                    "status": "BLIND_SPOT",
                    "tactic": tactic
                })

    return report
```

**ATT&CK Navigator Layer Generation:**
```python
# Color coding:
# Green (#66bb6a) = Detected with high confidence
# Yellow (#ffeb3b) = Logged only / partial detection
# Red (#ff6666) = Blind spot (executed, not detected)
# Gray (#d3d3d3) = Not tested

layer = {
    "gradient": {"colors": ["#ff6666", "#ffeb3b", "#66bb6a"], "minValue": 0, "maxValue": 100},
    "techniques": [{"techniqueID": tech_id, "color": color, "score": score}]
}
```

### Continuous Atomic Testing Pipeline

```
┌─────────────┐
│ 1. SELECT   │ Choose technique from threat intel or gap report
│  TECHNIQUE  │ Map to Atomic Red Team test ID
└──────┬──────┘
       │
┌──────▼──────┐
│ 2. EXECUTE  │ Run Invoke-AtomicTest with logging
│  ATOMIC TEST│ Record timestamp, hostname
└──────┬──────┘
       │
┌──────▼──────┐
│ 3. WAIT     │ 30-60 seconds for log ingestion
│  INGESTION  │
└──────┬──────┘
       │
┌──────▼──────┐
│ 4. QUERY    │ Did our detection rules fire?
│  SIEM       │
└──────┬──────┘
   YES │   NO
┌──────▼┐ ┌──▼──────────────────┐
│5a.GREEN│ │5b. WRITE NEW RULE  │
│Pass    │ │Sigma/SIEM rule     │
└──────┬┘ │5c. DEPLOY          │
       │  │5d. RE-EXECUTE      │
       │  └───────┬────────────┘
       │          │
┌──────▼──────────▼──┐
│ 6. CLEANUP         │
│  Invoke-AtomicTest │
│  -Cleanup          │
└──────┬─────────────┘
       │
┌──────▼──────┐
│ 7. NEXT     │ Select next technique
│  TECHNIQUE  │
└─────────────┘
```

### Priority Atomic Tests (by Prevalence)

| Technique | Name | Frequency |
|-----------|------|-----------|
| T1059.001 | PowerShell Execution | Very High |
| T1053.005 | Scheduled Task | High |
| T1547.001 | Registry Run Keys | High |
| T1003.001 | LSASS Memory | High |
| T1070.004 | File Deletion | High |
| T1218.011 | Rundll32 | High |
| T1082 | System Info Discovery | Medium |
| T1105 | Ingress Tool Transfer | Medium |

---

## 11. eBPF Security Monitoring (Tetragon)

### Kernel-Level Runtime Security

Tetragon operates at the Linux kernel level using eBPF, enabling:
- **Process lifecycle tracking** — every exec, exit across all pods
- **File integrity monitoring** — detect unauthorized reads/writes
- **Network observability** — all TCP/UDP connections with pod context
- **Runtime enforcement** — kill processes or deny operations in-kernel

**Performance:** < 1% overhead vs. traditional user-space agents

### TracingPolicy Examples

**Detect Container Escape:**
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-container-escape
spec:
  kprobes:
    - call: "__x64_sys_setns"
      syscall: true
      selectors:
        - matchNamespaces:
            - namespace: Pid
              operator: NotIn
              values: ["host_ns"]
          matchActions:
            - action: Sigkill
```

**Block Crypto-Miners:**
```yaml
spec:
  kprobes:
    - call: "security_bprm_check"
      selectors:
        - matchBinaries:
            operator: "In"
            values: ["/usr/bin/xmrig", "/tmp/xmrig"]
          matchActions:
            - action: Sigkill
```

**Monitor Sensitive File Access:**
```yaml
spec:
  kprobes:
    - call: "security_file_open"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values: ["/etc/shadow", "/etc/kubernetes/pki"]
          matchActions:
            - action: Post
```

### Key Metrics

| Metric | Alert Threshold |
|--------|-----------------|
| `tetragon_events_total` | Spike > 3x baseline |
| `tetragon_policy_events_total` | Any Sigkill action |
| `tetragon_missed_events_total` | > 0 sustained |

---

## 12. Cross-Cutting Best Practices

### Detection Engineering Principles

1. **Map every rule to ATT&CK** — track coverage gaps quantitatively
2. **Test before deploy** — Atomic Red Team validation for every new rule
3. **Tune continuously** — quarterly FP rate review, threshold adjustment
4. **Enrich aggressively** — asset, identity, threat intel lookups
5. **Version control everything** — Sigma rules in Git with CI/CD
6. **Measure MTTD/MTTR** — know your detection and response times
7. **Purple team regularly** — quarterly exercises minimum
8. **Consolidate before alerting** — RBA > threshold alerts
9. **Maintain allowlists** — documented, reviewed quarterly
10. **Document tuning decisions** — rationale, approved by, detection impact

### Detection Coverage Targets

| Tactic | Target Coverage |
|--------|----------------|
| Initial Access | > 75% |
| Execution | > 80% |
| Persistence | > 70% |
| Privilege Escalation | > 65% |
| Credential Access | > 65% |
| Lateral Movement | > 60% |
| Exfiltration | > 50% |
| Impact | > 50% |
| **Overall** | **> 60% of relevant techniques** |

### Data Source Requirements

| Data Source | ATT&CK Techniques Covered | Priority |
|------------|---------------------------|----------|
| Windows Security Event Logs | 4624/4625/4688/4698/4662/4672 | Critical |
| Sysmon (Events 1,3,7,8,10,11,13) | Process, network, file, registry, memory | Critical |
| PowerShell Script Block Logging (4104) | T1059.001 | High |
| DNS Query Logs | T1071.004, T1568 | High |
| Proxy/HTTP Logs | T1071.001, T1041 | High |
| Network Flow (NetFlow/sFlow) | T1048, T1049 | Medium |
| EDR Telemetry | Full endpoint behavior | High |
| Cloud Audit Logs | Cloud-specific TTPs | High |

---

## References

- **Skills Synthesized:** 19 Anthropic Cybersecurity Skills (detection engineering, SIEM, endpoint, network, purple team)
- **Frameworks:** MITRE ATT&CK, Sigma, pySigma, Atomic Red Team, ATT&CK Navigator
- **Platforms:** Splunk ES, Elastic Security, Microsoft Sentinel, CrowdStrike Falcon, Wazuh, Suricata, Snort 3, Tetragon
- **Standards:** NIST CSF (DE.CM-01, DE.AE-02, RS.MA-01), D3FEND
