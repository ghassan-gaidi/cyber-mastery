# Local STIX Query: MITRE ATT&CK Enterprise Matrix

## Location

- **Dataset:** `/home/leo/Desktop/cyber/enterprise-attack.json` (46MB, 25,842 objects, STIX 2.1)
- **Query tool:** `/home/leo/Desktop/cyber/attack.py`

## Why local is better

- Zero network — no TAXII server dependency, no rate limits, instant queries
- Full dataset: 1,716 techniques, 378 intrusion sets, 729 malware, 21,025 relationships
- Works offline in sessions where web tools aren't available
- The STIX bundle is updated to mid-2026 (modified date 2026-04-14)

## Query tool usage

```bash
cd /home/leo/Desktop/cyber

# Technique details by ID or name
python3 attack.py info T1190
python3 attack.py info "Exploit Public-Facing Application"
python3 attack.py info T1078.001

# List techniques in a tactic (optionally filtered by platform)
python3 attack.py tactic initial-access
python3 attack.py tactic lateral-movement Linux
python3 attack.py tactic privilege-escalation Containers

# All techniques for a platform
python3 attack.py platform Linux
python3 attack.py platform Containers

# Show group with all associated techniques
python3 attack.py group apt29
python3 attack.py group G0016
python3 attack.py group "Lazarus Group"

# Keyword search across technique names and descriptions
python3 attack.py search container
python3 attack.py search dll sideloading
python3 attack.py search credential

# Summary statistics
python3 attack.py stats
```

## Dataset structure

| Object type | Count | Description |
|---|---|---|
| `relationship` | 21,025 | Edges connecting techniques ↔ groups, malware, mitigations, etc. |
| `x-mitre-analytic` | 1,758 | Detection analytics (pseudocode detection logic) |
| `attack-pattern` | 1,716 | Techniques + sub-techniques (858 parent + 858 sub) |
| `malware` | 729 | Known malware families with aliases |
| `course-of-action` | 268 | Mitigations mapped to techniques |
| `intrusion-set` | 189 | APT groups with aliases and associated techniques |
| `x-mitre-data-component` | 109 | Atomic data sources for telemetry |
| `tool` | 95 | Known offensive/defensive tools |
| `campaign` | 56 | Documented intrusion campaigns |
| `x-mitre-data-source` | 38 | High-level data source categories |
| `x-mitre-tactic` | 15 | Tactic columns (TA0001–TA0043) |

## Platform coverage

| Platform | Techniques |
|---|---|
| Windows | 1,182 |
| macOS | 882 |
| Linux | 838 |
| ESXi | 242 |
| IaaS | 224 |
| Network Devices | 210 |
| Containers | 100 |

## When to use local vs TAXII

- **Use local** for fast lookups, platform/tactic filtering, group intel, keyword search, bulk analysis
- **Use TAXII (`attackcti`)** when you need fully up-to-date data (bundle may lag by a few weeks), or procedure-level examples with full descriptions

The local tool resolves by STIX ID, external ID (TXXXX/TAXXXX/GXXXX/MXXXX), or fuzzy name match. Returns up to 10 candidates on partial matches.
