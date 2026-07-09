# DFIR Mastery — Digital Forensics & Incident Response Comprehensive Reference

> Synthesized from 35+ cybersecurity skills (Anthropic collection). Covers the full DFIR lifecycle from evidence acquisition to forensic reporting.

---

## Table of Contents

1. [Incident Response Lifecycle](#1-incident-response-lifecycle)
2. [Disk Forensics Methodology](#2-disk-forensics-methodology)
3. [Memory Forensics (Volatility)](#3-memory-forensics-volatility)
4. [Timeline Reconstruction](#4-timeline-reconstruction)
5. [Windows Artifact Analysis](#5-windows-artifact-analysis)
6. [Linux Forensics](#6-linux-forensics)
7. [Browser and Email Forensics](#7-browser-and-email-forensics)
8. [Cloud Forensics](#8-cloud-forensics)
9. [Evidence Acquisition and Chain of Custody](#9-evidence-acquisition-and-chain-of-custody)
10. [Master Tool Reference](#10-master-tool-reference)
11. [MITRE ATT&CK Cross-Reference](#11-mitre-attack-cross-reference)

---

## 1. Incident Response Lifecycle

### 1.1 Preparation
- Forensic workstation with tools: Volatility 3, KAPE, Autopsy, Eric Zimmerman Tools, Plaso
- Write-blockers (hardware: Tableau T35u; software: `blockdev --setro`)
- Secure evidence storage with chain-of-custody documentation
- Memory acquisition tools: WinPMEM, FTK Imager, Magnet RAM Capture, LiME
- Velociraptor endpoint agent deployed across fleet for scalable collection

### 1.2 Evidence Preservation (Order of Volatility)
```
1. System memory (RAM)          ← MOST VOLATILE — collect first
2. Network connections/routing tables
3. Running processes and open files
4. Disk contents (file system)
5. Removable media
6. Logs and backup data         ← LEAST VOLATILE
```

**Memory Acquisition Commands:**
```bash
# Windows
winpmem_mini_x64.exe memdump.raw

# Linux
sudo insmod lime.ko "path=/evidence/memory.lime format=lime"

# Volatile data collection (Windows)
Get-Process | Export-Csv "evidence\processes.csv"
netstat -anob > "evidence\netstat.txt"
query user > "evidence\logged_users.txt"
schtasks /query /fo CSV /v > "evidence\scheduled_tasks.csv"
ipconfig /displaydns > "evidence\dns_cache.txt"
```

### 1.3 Containment
- Isolate compromised systems (network isolation via forensic SG/VLAN)
- Preserve volatile evidence before containment actions
- Document all containment actions with timestamps

### 1.4 Eradication
- Identify and remove persistence mechanisms
- Remove malware from all affected systems
- Reset compromised credentials
- Patch exploited vulnerabilities

### 1.5 Recovery
- Restore systems from known-good backups
- Verify system integrity before reconnection
- Monitor for reinfection indicators

### 1.6 Lessons Learned
- Document findings in structured forensic report
- Map attack chain to MITRE ATT&CK
- Update detection rules and playbooks

---

## 2. Disk Forensics Methodology

### 2.1 Forensic Imaging

**Using dcfldd (preferred for forensics):**
```bash
# Bit-for-bit copy with built-in hash verification
dcfldd if=/dev/sdb of=/evidence/WKSTN-042.dd \
  hash=sha256 hashlog=/evidence/WKSTN-042.sha256 \
  bs=4096 conv=noerror,sync

# Split large images into segments
dcfldd if=/dev/sdb of=/evidence/evidence.dd \
  hash=sha256 bs=4096 split=2G splitformat=aa

# Verify image integrity
sha256sum /evidence/WKSTN-042.dd
diff <(sha256sum /dev/sdb) <(sha256sum /evidence/WKSTN-042.dd)
```

**Using FTK Imager (Windows GUI):**
1. Connect drive through write blocker
2. File > Create Disk Image > Physical Drive > E01 format
3. Enable "Verify images after creation"
4. Record source and image hash values

### 2.2 File System Analysis with Autopsy

**Key Autopsy Ingest Modules:**
- Recent Activity (browser history, downloads, cookies)
- Hash Lookup (NSRL known-bad filtering)
- File Type Identification (signature-based, not extension)
- Keyword Search (full-text indexing)
- Extension Mismatch Detector
- Encryption Detection

**Sleuth Kit CLI Workflow:**
```bash
# Verify image
img_stat evidence.dd
mmls evidence.dd                    # Partition layout

# List files including deleted
fls -r -o 2048 evidence.dd
fls -rd -o 2048 evidence.dd         # Deleted files only

# Recover specific file by inode
icat -o 2048 evidence.dd 14523 > recovered_file.docx

# Generate body file for timeline
fls -r -m "/" -o 2048 evidence.dd > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv
```

### 2.3 File Carving with Foremost

```bash
# Carve all supported file types
foremost -t all -i evidence.dd -o /carved/foremost_all/

# Carve specific types from unallocated space
blkls -o 2048 evidence.dd > unallocated.dd
foremost -t jpg,png,pdf,doc,xls,zip -i unallocated.dd -o /carved/

# Custom configuration for PST, EML, EVTX
foremost -c custom_foremost.conf -i evidence.dd -o /carved/custom/

# Validate carved files
find /carved/ -type f -exec file {} \; | grep -v "data\|empty"
```

### 2.4 File System Artifacts (NTFS)

**$MFT Analysis:**
- MFTECmd parses MFT entries showing InUse flag (deleted = False)
- $STANDARD_INFORMATION vs $FILE_NAME timestamps detect timestomping
- $UsnJrnl:$J records all file changes (create, delete, rename)
- $LogFile stores NTFS transaction records

**Slack Space:**
- File slack: unused bytes between file end and cluster boundary
- MFT slack: space between used portion and 1024-byte record end
- Zone.Identifier ADS tracks download origin (ZoneId=3 = Internet)

**Alternate Data Streams:**
```bash
# Find ADS
fls -r -o 2048 evidence.dd | grep ":"

# Extract ADS content
icat -o 2048 evidence.dd 14523:hidden_stream > extracted_ads.bin

# Check Zone.Identifier (download origin)
icat -o 2048 evidence.dd inode:Zone.Identifier
```

---

## 3. Memory Forensics (Volatility)

### 3.1 Volatility 3 Plugin Reference

**Process Analysis:**
```bash
vol -f memory.dmp windows.info          # OS identification
vol -f memory.dmp windows.pslist        # Active processes
vol -f memory.dmp windows.pstree        # Parent-child tree
vol -f memory.dmp windows.psscan        # Hidden/unlinked processes
vol -f memory.dmp windows.cmdline       # Command-line arguments
vol -f memory.dmp windows.envars        # Environment variables
```

**Malware Detection:**
```bash
vol -f memory.dmp windows.malfind       # Injected code (RWX + PE headers)
vol -f memory.dmp windows.hollowfind    # Process hollowing
vol -f memory.dmp windows.driverscan    # Suspicious drivers
vol -f memory.dmp windows.modules       # Loaded kernel modules
```

**Network & Credentials:**
```bash
vol -f memory.dmp windows.netscan       # Active network connections
vol -f memory.dmp windows.hashdump      # NTLM password hashes
vol -f memory.dmp windows.lsadump       # LSA secrets
vol -f memory.dmp windows.cachedump     # Cached domain credentials
vol -f memory.dmp windows.clipboard     # Clipboard contents
```

**File & Registry:**
```bash
vol -f memory.dmp windows.filescan      # Files in memory
vol -f memory.dmp windows.dumpfiles --virtaddr 0xFA8001234560
vol -f memory.dmp windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

**YARA Scanning:**
```bash
vol -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar
vol -f memory.dmp yarascan.YaraScan --yara-rules "rule FindC2 { strings: $s1 = \"gate.php\" condition: $s1 }"
```

### 3.2 Hidden Process Detection

Compare `pslist` vs `psscan` output:
```python
pslist_pids = {e.get("PID") for e in pslist}
psscan_pids = {e.get("PID") for e in psscan}
hidden = psscan_pids - pslist_pids  # These are rootkit-hidden
```

### 3.3 Suspicious Process Indicators
- svchost.exe not spawned by services.exe (wrong parent)
- Multiple instances of lsass.exe (should be only one)
- Misspelled names (scvhost.exe, lssas.exe)
- cmd.exe/powershell.exe spawned by WINWORD.EXE or browser
- Processes running from %TEMP%, %APPDATA%
- Processes with no parent (orphaned)

### 3.4 Linux Memory (LiME + Volatility)

```bash
# Acquisition
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Analysis
vol3 -f memory.lime linux.pslist
vol3 -f memory.lime linux.bash          # Bash command history
vol3 -f memory.lime linux.sockstat      # Network connections
vol3 -f memory.lime linux.lsmod         # Loaded kernel modules
vol3 -f memory.lime linux.malfind       # Injected code
```

---

## 4. Timeline Reconstruction

### 4.1 Super Timeline with Plaso

```bash
# Generate Plaso storage from disk image
log2timeline.py --storage-file timeline.plaso evidence.dd

# Targeted processing with specific parsers
log2timeline.py --parsers "winevtx,prefetch,mft,usnjrnl,lnk,chrome_history" \
  --storage-file timeline.plaso evidence.dd

# Filter to incident window and export
psort.py -o l2tcsv -w incident_timeline.csv timeline.plaso \
  "date > '2024-01-15' AND date < '2024-01-20'"

# Export JSON Lines for Timesketch/SIEM
psort.py -o json_line -w timeline.jsonl timeline.plaso
```

### 4.2 Windows Event Log Timeline

**Critical Event IDs:**
| Event ID | Description | Forensic Value |
|----------|-------------|----------------|
| 4624 | Successful logon | Track access patterns |
| 4625 | Failed logon | Brute force detection |
| 4648 | Explicit credential logon | Lateral movement |
| 4672 | Special privileges assigned | Privilege escalation |
| 4688 | Process creation | Execution evidence |
| 4697 | Service installed | Persistence |
| 4698 | Scheduled task created | Persistence |
| 4720 | User account created | Backdoor accounts |
| 4732 | Member added to security group | Privilege escalation |
| 1102 | Audit log cleared | Anti-forensics |

**Logon Types:**
- Type 2: Interactive (console)
- Type 3: Network (SMB, WMI, PowerShell Remoting)
- Type 10: Remote interactive (RDP)

### 4.3 Chainsaw + Hayabusa

```bash
# Chainsaw: Sigma-based detection
chainsaw hunt /evtx/ -s /sigma/rules/ \
  --mapping sigma-event-logs-all.yml --csv

# Hayabusa: Fast timeline generation
hayabusa csv-timeline -d /evtx/ -o timeline.csv -p verbose
hayabusa logon-summary -d /evtx/ -o logon_summary.csv
```

### 4.4 EZ Tools Timeline Integration

```powershell
# KAPE automated collection and processing
kape.exe --tsource E: --tdest Output\Collection --target KapeTriage \
  --mdest Output\Processed --module !EZParser

# Open processed CSVs in Timeline Explorer for visual analysis
TimelineExplorer.exe "Output\Processed\MFT_output.csv"
```

---

## 5. Windows Artifact Analysis

### 5.1 Prefetch Files

**Location:** `C:\Windows\Prefetch\*.pf`
**Tool:** PECmd (Eric Zimmerman)

```powershell
PECmd.exe -d "C:\Windows\Prefetch" --csv output\ --csvf prefetch.csv
```

**Key fields:** Executable name, run count, last 8 execution timestamps (Win10+), referenced files/directories, volume serial number.

**Prefetch versions:**
- v17: Windows XP
- v23: Vista/7 (1 timestamp)
- v26: Windows 8.1 (8 timestamps)
- v30: Windows 10 (MAM compressed, 8 timestamps)

**Suspicious patterns:**
- Mimikatz, PsExec, BloodHound, Cobalt Strike tool names
- PowerShell/CMD/WSCRIPT/MSHTA execution
- Anti-forensic tools (CCleaner, SDelete, wevtutil)

### 5.2 Amcache

**Location:** `C:\Windows\appcompat\Programs\Amcache.hve`
**Tool:** AmcacheParser (Eric Zimmerman)

```powershell
AmcacheParser.exe -f "Amcache.hve" --csv Output\
AmcacheParser.exe -f "Amcache.hve" -w nsrl_sha1.txt --csv Output\  # Whitelist filter
AmcacheParser.exe -f "Amcache.hve" -b malware_sha1.txt --csv Output\  # Known-bad
```

**Output files:** AssociatedFileEntries (SHA-1 hashes, paths, timestamps), ProgramEntries (install metadata), DriverBinaries (loaded drivers), DeviceContainers (USB history).

**Forensic value:** Proves file existence and metadata registration. LinkDate vs FileKeyLastWriteTimestamp comparison detects timestomping. Correlate with Prefetch for execution confirmation.

### 5.3 Registry Analysis

**Key hives:** SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat

```powershell
# RegRipper automated extraction
perl rip.pl -r NTUSER.DAT -f ntuser
perl rip.pl -r SYSTEM -f system
perl rip.pl -r SOFTWARE -f software
perl rip.pl -r SAM -f sam

# RECmd with batch files
RECmd.exe --bn RECmd_Batch_MC.reb -d "Registry" --csv Output\
```

**Critical registry artifacts:**
| Artifact | Location | Evidence |
|----------|----------|----------|
| Run/RunOnce | `Microsoft\Windows\CurrentVersion\Run` | Autostart persistence |
| UserAssist | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Program execution (ROT13 encoded) |
| USBSTOR | `ControlSet*\Enum\USBSTOR` | USB device history |
| MountPoints2 | `Explorer\MountPoints2` | User USB access |
| ShimCache | `SYSTEM\AppCompatCache` | Program existence |
| BAM/DAM | `SYSTEM\CurrentControlSet\Services\Bam\State` | Recent program execution (Win10+) |

### 5.4 LNK Files and Jump Lists

**LNK file locations:** `%AppData%\Microsoft\Windows\Recent\`, Desktop, Startup folder

```powershell
LECmd.exe -d "Recent\" --csv Output\ --csvf lnk_analysis.csv
JLECmd.exe -d "AutomaticDestinations\" --csv Output\ --csvf jumplists.csv
```

**Key LNK fields:** Target path, target timestamps, volume serial, machine ID, MAC address, command-line arguments, run window state.

**Jump List AppIDs:**
| Hash | Application |
|------|-------------|
| 1b4dd67f29cb1962 | Explorer Recent |
| 9b9cdc69c1c24e2b | Notepad |
| 9d1f905ce5044aee | Microsoft Excel |
| a4a5324453625195 | Microsoft Word |

### 5.5 Shellbags

**Registry locations:** NTUSER.DAT `Shell\BagMRU` + `Shell\Bags`; UsrClass.dat equivalents

```powershell
SBECmd.exe -d "Registry\" --csv Output\ --csvf shellbags.csv
```

**Evidence value:** Proves folder browsing activity (even deleted folders). Shows access to USB drives, network shares, zip archives. Only created through Explorer shell (not command-line).

### 5.6 USB Device History

```bash
# Parse USBSTOR from SYSTEM hive
python3 -c "
from Registry import Registry
reg = Registry.Registry('SYSTEM')
for device in reg.open('ControlSet001\Enum\USBSTOR').subkeys():
    for instance in device.subkeys():
        print(f'{device.name()}: Serial={instance.name()}, Last={instance.timestamp()}')
"

# SetupAPI first-connection timestamps
grep -i "USBSTOR\|USB\\\\VID" setupapi.dev.log
```

### 5.7 MFT Deleted File Recovery

```powershell
MFTECmd.exe -f "$MFT" --csv Output\ --csvf mft_analysis.csv
MFTECmd.exe -f "$J" --csv Output\ --csvf usn_journal.csv
```

**Deleted file indicators:** InUse = False, parent path shows original location, file size preserved, timestamps persist.

**Timestomping detection:** Compare $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) timestamps. If $SI Created < $FN Created, timestomping is indicated.

---

## 6. Linux Forensics

### 6.1 Log Files

| Log | Path | Contents |
|-----|------|----------|
| auth.log/secure | `/var/log/auth.log` or `/var/log/secure` | Authentication, sudo, SSH |
| syslog/messages | `/var/log/syslog` or `/var/log/messages` | General system messages |
| kern.log | `/var/log/kern.log` | Kernel events, USB |
| wtmp | `/var/log/wtmp` | Login/logout records |
| btmp | `/var/log/btmp` | Failed login attempts |
| audit.log | `/var/log/audit/audit.log` | Linux Audit Framework |
| journal | `/var/log/journal/` | systemd binary journal |

### 6.2 Authentication Analysis

```bash
# Successful SSH logins
grep "Accepted" /var/log/auth.log

# Failed SSH (brute force detection)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# Sudo commands
grep "sudo:" /var/log/auth.log | grep "COMMAND"

# Login history
last -f /var/log/wtmp
lastb -f /var/log/btmp   # Failed logins

# Systemd journal
journalctl --output=json --since "2024-01-15" --until "2024-01-20"
```

### 6.3 Persistence Mechanisms

```bash
# Cron jobs
cat /etc/crontab
ls -la /var/spool/cron/crontabs/
grep "CRON" /var/log/syslog

# Systemd services
find /etc/systemd/system/ -name "*.service"

# SSH authorized_keys (backdoor detection)
find /home/ /root/ -name "authorized_keys" -exec cat {} \;

# LD_PRELOAD hijacking
grep -r "LD_PRELOAD" /etc/
cat /etc/ld.so.preload

# SUID binaries (privilege escalation)
find / -perm -4000 -type f 2>/dev/null
```

### 6.4 Shell History Analysis

```python
suspicious_commands = [
    'wget', 'curl', 'nc ', 'ncat', 'python -c', 'python3 -c',
    'base64', 'chmod 777', 'chmod +s', '/dev/tcp', 'nmap',
    'hydra', 'john', 'hashcat', 'useradd', 'iptables -F',
    'history -c', 'crontab', 'systemctl enable', 'ssh-keygen',
    'tar czf', 'openssl enc', 'shred', '/tmp/', '/dev/shm/'
]
```

### 6.5 Rootkit Detection

```bash
# Check for unknown system binaries
find /usr/bin/ /usr/sbin/ /bin/ /sbin/ -type f -exec sha256sum {} \;

# Check for modified PAM configuration
diff /etc/pam.d/ /baseline/pam.d/

# Check kernel modules
ls -la /lib/modules/$(uname -r)/extra/
```

---

## 7. Browser and Email Forensics

### 7.1 Browser Artifact Locations

**Chrome (Windows):** `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- `History` — browsing history, downloads
- `Cookies` — session cookies
- `Login Data` — saved passwords (DPAPI encrypted)
- `Bookmarks` — saved bookmarks

**Firefox:** `%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\`
- `places.sqlite` — history + bookmarks
- `cookies.sqlite` — cookies
- `formhistory.sqlite` — form fills

**Edge (Chromium):** `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`

### 7.2 Chrome History Query

```sql
SELECT urls.url, urls.title,
  datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit,
  urls.visit_count
FROM urls ORDER BY urls.last_visit_time DESC;
```

**Chrome timestamp epoch:** Microseconds since January 1, 1601 (WebKit epoch)
**Firefox timestamp epoch:** Microseconds since January 1, 1970 (Unix epoch)

### 7.3 Email Header Analysis

**Key headers:**
| Header | Forensic Value |
|--------|---------------|
| Received | Delivery chain (read bottom to top) |
| X-Originating-IP | Sender's actual IP |
| Message-ID | Correlation identifier |
| Return-Path | Bounce address (may differ from From) |
| DKIM-Signature | Content integrity verification |
| Authentication-Results | SPF/DKIM/DMARC results |

**SPF/DKIM/DMARC validation:**
```bash
dig TXT example.com +short | grep "v=spf1"     # SPF
dig TXT selector1._domainkey.example.com +short  # DKIM
dig TXT _dmarc.example.com +short                # DMARC
```

**Phishing indicators:**
- From/Reply-To mismatch
- Lookalike domain (Levenshtein distance)
- Recently registered domain
- SPF fail or DKIM missing
- URL obfuscation (display text != href)

### 7.4 PST/OST Email Forensics

```bash
# Export all items from PST
pffexport -m all evidence.pst -t exported_pst

# Export recovered/deleted items
pffexport -m recovered evidence.pst -t recovered_items

# Get PST info
pffinfo evidence.pst
```

**PST locations:**
- Outlook 2016+: `%USERPROFILE%\Documents\Outlook Files\*.pst`
- OST cache: `%LOCALAPPDATA%\Microsoft\Outlook\*.ost`

---

## 8. Cloud Forensics

### 8.1 Evidence Preservation

**AWS:**
```bash
# Snapshot compromised EC2 volumes
aws ec2 create-snapshot --volume-id $vol --description "Forensic snapshot"

# Isolate instance
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID --groups sg-forensic-isolation
```

**Azure:**
```bash
az snapshot create --resource-group forensics-rg --name case-snapshot --source /disks/vm-osdisk
```

**GCP:**
```bash
gcloud compute disks snapshot compromised-disk --snapshot-names=forensic-snapshot
```

### 8.2 Cloud API Log Forensics

**AWS CloudTrail:**
```bash
aws cloudtrail lookup-events --start-time "2024-01-15T00:00:00Z" \
  --end-time "2024-01-20T23:59:59Z" --max-results 1000
```

**Azure Activity Log:**
```bash
az monitor activity-log list --start-time "2024-01-15T00:00:00Z" --output json
```

**GCP Audit Logs:**
```bash
gcloud logging read 'logName="projects/PROJECT/logs/cloudaudit.googleapis.com/activity"' --format=json
```

### 8.3 AWS Athena Forensic Queries

**Detect privilege escalation:**
```sql
SELECT eventtime, useridentity.arn AS actor, eventname, sourceipaddress
FROM cloud_forensics.cloudtrail_logs
WHERE eventname IN ('AttachUserPolicy', 'PutUserPolicy', 'CreateAccessKey', 'AssumeRole')
ORDER BY eventtime DESC;
```

**Detect S3 data exfiltration:**
```sql
SELECT eventtime, useridentity.arn, eventname,
  json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
  sourceipaddress
FROM cloud_forensics.cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject', 'CopyObject', 'PutBucketPolicy')
  AND sourceipaddress NOT LIKE '10.%'
ORDER BY eventtime DESC;
```

**Detect lateral movement via VPC Flow Logs:**
```sql
SELECT srcaddr, dstaddr, dstport, SUM(bytes) AS total_bytes
FROM cloud_forensics.vpc_flow_logs
WHERE action = 'ACCEPT' AND dstport IN (22, 3389, 445, 135)
GROUP BY srcaddr, dstaddr, dstport
HAVING COUNT(*) > 100;
```

### 8.4 Cloud Storage Acquisition

**API-based (Google Drive example):**
```python
from googleapiclient.discovery import build
service = build("drive", "v3", credentials=creds)
files = service.files().list(q="", pageSize=1000,
    fields="files(id, name, size, createdTime, modifiedTime, md5Checksum)").execute()
```

**Local sync client artifacts:**
| Service | Local Database | Cache |
|---------|---------------|-------|
| OneDrive | SyncEngineDatabase.db | `%LOCALAPPDATA%\Microsoft\OneDrive\cache\` |
| Google Drive | metadata_sqlite_db | `%LOCALAPPDATA%\Google\DriveFS\` |
| Dropbox | filecache.dbx (encrypted) | `%APPDATA%\Dropbox\.dropbox.cache\` |

---

## 9. Evidence Acquisition and Chain of Custody

### 9.1 Chain of Custody Record

```
Case ID:          INC-2024-001
Evidence ID:      EVD-001
Description:      Samsung 870 EVO 500GB SSD
Serial Number:    S5XXNJ0R912345
Source Host:      WKSTN-042
Acquired By:      [Analyst Name]
Date/Time:        2024-01-15T16:30:00Z
Write Blocker:    Tableau T35u (S/N: T35U-12345)
Source Hash:      SHA-256: a1b2c3d4...
Image Hash:       SHA-256: a1b2c3d4... (MATCH)
```

### 9.2 Write Blocking

**Hardware:** Tableau T35u, Tableau T356789iu
**Software:**
```bash
blockdev --setro /dev/sdb     # Linux
blockdev --getro /dev/sdb     # Verify (output: 1)
```

### 9.3 Hash Verification Protocol

1. Hash source BEFORE imaging: `sha256sum /dev/sdb > source_hash_before.txt`
2. Hash during acquisition (dcfldd built-in)
3. Hash image AFTER acquisition: `sha256sum evidence.dd > image_hash.txt`
4. Re-hash source AFTER imaging: `sha256sum /dev/sdb > source_hash_after.txt`
5. Compare source hashes (before == after = no modification)
6. Compare source hash == image hash (bit-for-bit match)

### 9.4 Velociraptor for Scalable Collection

```sql
-- Windows triage collection
SELECT * FROM Artifact.Windows.KapeFiles.Targets(
  Device="C:", _EventLogs=TRUE, _Prefetch=TRUE,
  _RegistryHives=TRUE, _WebBrowsers=TRUE
)

-- Linux forensic artifacts
SELECT * FROM Artifact.Linux.Sys.AuthLogs()
SELECT * FROM Artifact.Linux.Forensics.BashHistory()
SELECT * FROM Artifact.Linux.Sys.Crontab()
SELECT * FROM Artifact.Linux.Ssh.AuthorizedKeys()
```

### 9.5 Forensic Report Structure

```
1. Executive Summary
2. Scope and Methodology
3. Evidence Inventory (with chain of custody)
4. Timeline of Events
5. Findings and Analysis
   - Initial access vector
   - Persistence mechanisms
   - Lateral movement
   - Data access/exfiltration
6. Indicators of Compromise (IOCs)
7. Recommendations
8. Appendices (tool output, hashes, raw evidence)
```

---

## 10. Master Tool Reference

| Tool | Purpose | Platform |
|------|---------|----------|
| **Volatility 3** | Memory forensics framework | Cross-platform |
| **Autopsy/Sleuth Kit** | Disk forensics platform | Cross-platform |
| **FTK Imager** | Forensic imaging + memory acquisition | Windows |
| **Plaso/log2timeline** | Super timeline creation | Cross-platform |
| **KAPE** | Automated triage collection + processing | Windows |
| **MFTECmd** | $MFT and $UsnJrnl parser | Cross-platform |
| **PECmd** | Prefetch file parser | Cross-platform |
| **RECmd** | Registry hive parser | Cross-platform |
| **EvtxECmd** | Windows Event Log parser | Cross-platform |
| **LECmd** | LNK file parser | Cross-platform |
| **JLECmd** | Jump List parser | Cross-platform |
| **SBECmd** | Shellbag parser | Cross-platform |
| **Timeline Explorer** | Visual CSV timeline analysis | Windows |
| **AmcacheParser** | Amcache.hve parser | Cross-platform |
| **RegRipper** | Registry artifact extraction | Cross-platform |
| **Chainsaw** | Sigma-based EVTX analysis | Cross-platform |
| **Hayabusa** | Fast timeline generation | Cross-platform |
| **Velociraptor** | Scalable endpoint collection | Cross-platform |
| **dcfldd** | Forensic disk imaging with hashing | Linux |
| **Foremost/Scalpel** | File carving | Linux |
| **bulk_extractor** | Feature extraction from raw data | Linux |
| **Hindsight** | Chrome/Chromium forensic analysis | Cross-platform |
| **pffexport** | PST/OST file export | Cross-platform |
| **Timesketch** | Collaborative timeline analysis | Cross-platform |

---

## 11. MITRE ATT&CK Cross-Reference

| ATT&CK Technique | Evidence Sources | Key Artifacts |
|-------------------|-----------------|---------------|
| T1059 - Command Scripting | Event Logs 4104, 4688 | PowerShell Script Block Logs, Prefetch |
| T1053 - Scheduled Task | Event Logs 4698, 4702 | Task Scheduler logs, Registry |
| T1547 - Boot/Logon Autostart | Registry, Event Logs | Run keys, Services, WMI |
| T1003 - OS Credential Dumping | Memory, Logs | LSASS access, Mimikatz Prefetch |
| T1021 - Remote Services | Event Logs 4624 | Logon Type 3/10, PsExec |
| T1070 - Indicator Removal | Event Logs 1102 | Log clearing, file deletion |
| T1562 - Impair Defenses | System Logs | AV disabled, firewall rules |
| T1078 - Valid Accounts | CloudTrail, Event Logs | Unusual IP, off-hours access |
| T1190 - Exploit Public App | ALB/Access Logs | SQLi, XSS patterns |
| T1090 - Proxy | Network Logs | Unusual outbound connections |

---

## Appendix: Quick Reference Commands

### Disk Forensics
```bash
dcfldd if=/dev/sdb of=evidence.dd hash=sha256 bs=4096 conv=noerror,sync
mmls evidence.dd                    # Partition layout
fls -r -m "/" -o 2048 evidence.dd > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv
foremost -t all -i evidence.dd -o /carved/
```

### Memory Forensics
```bash
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.malfind
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.hashdump
```

### Timeline
```bash
log2timeline.py --storage-file timeline.plaso evidence.dd
psort.py -o l2tcsv -w timeline.csv timeline.plaso
```

### Windows Artifacts
```powershell
PECmd.exe -d "C:\Windows\Prefetch" --csv output\
MFTECmd.exe -f "$MFT" --csv output\
RECmd.exe --bn BatchExamples\RECmd_Batch_MC.reb -d "Registry" --csv output\
EvtxECmd.exe -d "Logs\" --csv output\
LECmd.exe -d "Recent\" --csv output\
```

### Cloud
```bash
aws cloudtrail lookup-events --start-time "2024-01-15T00:00:00Z"
aws ec2 create-snapshot --volume-id $vol
```

---

*Last updated: 2026-07-09. Source: Anthropic Cybersecurity Skills Collection (35+ skills synthesized).*
