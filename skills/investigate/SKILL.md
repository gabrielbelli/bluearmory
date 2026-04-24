---
name: investigate
description: Investigate any indicator (IP, hash, process name, or string) across Graylog and IRIS — auto-detects type, resolves stream IDs, runs targeted per-stream queries, applies analyst heuristics, and auto-pivots on the highest-risk finding.
---

Investigate the indicator: $ARGUMENTS

Expected format: `<indicator> [last <N> days]`
Default time window: last 14 days. Convert to `range_seconds` for all MCP calls.

Examples:
  `/investigate 192.168.1.100`
  `/investigate 4d5f3b9a8c1e2d3f4e5a6b7c8d9e0f1a`
  `/investigate mimikatz.exe`
  `/investigate jdoe last 7 days`

---

## Phase 0 — Discover and map streams

Call `list_streams()` once. Read every stream title returned.

Stream names in this environment are company/client names — there are no generic
names like "firewall" or "proxy". You must infer what each stream contains from
context clues in the title, description, and index set name.

Map each stream to one of these roles based on what you know about the environment:

| Role | What to look for in the title/description |
|---|---|
| `fw_id` | Network traffic, firewall, perimeter, NAT, VPN, router, NGFW logs |
| `proxy_id` | Web proxy, URL filtering, DNS, HTTP/HTTPS traffic, Squid, Zscaler |
| `edr_id` | Endpoint, EDR, AV, CrowdStrike, Defender, Sysmon, process events |

Rules:
- A stream may cover more than one role — assign it to the most specific one.
- If no stream clearly maps to a role, set that role's id to `None` and omit
  `stream_id` from queries that would have used it (fall back to all streams).
- If the indicator type makes a role irrelevant (e.g. hash investigation doesn't
  need `proxy_id`), skip resolving that role entirely.
- Print the resolved mapping before proceeding so the analyst can verify:
  `Streams: fw=<title>, proxy=<title>, edr=<title>`

Store the resolved ids as `fw_id`, `proxy_id`, `edr_id` and use them throughout Phase 2.

---

## Phase 1 — Classify the indicator

| Pattern | Type |
|---|---|
| Matches `\d{1,3}(\.\d{1,3}){3}` | **IPv4** |
| Exactly 32 hex chars | **MD5 hash** |
| Exactly 40 hex chars | **SHA1 hash** |
| Exactly 64 hex chars | **SHA256 hash** |
| Ends in `.exe .dll .ps1 .bat .vbs .sh .py` | **Process / file name** |
| Anything else | **Generic string** (username, hostname, command fragment, domain, IOC string) |

---

## Phase 2 — Run queries

> Field names vary between Graylog deployments. If a query returns 0 results,
> retry with the next field name variant before giving up.

### IP investigation

Run all of the following **in parallel**:

**Outbound (IP as source)** — scoped to `fw_id` — try `srcip`, `src_ip`, `source_ip` until one returns results:
- `search_terms(field="dstip",   query='srcip:"<ip>"', range_seconds=N, size=20, stream_id=fw_id)` — top destination IPs
- `search_terms(field="dport",   query='srcip:"<ip>"', range_seconds=N, size=20, stream_id=fw_id)` — top destination ports
- `search_terms(field="action",  query='srcip:"<ip>"', range_seconds=N, size=10, stream_id=fw_id)` — firewall actions
- `search_terms(field="srcuser", query='srcip:"<ip>"', range_seconds=N, size=10, stream_id=fw_id)` — users at this source

**Inbound (IP as destination)** — scoped to `fw_id` — try `dstip`, `dst_ip`, `destination_ip`:
- `search_terms(field="srcip",  query='dstip:"<ip>"', range_seconds=N, size=20, stream_id=fw_id)` — top source IPs
- `search_terms(field="action", query='dstip:"<ip>"', range_seconds=N, size=10, stream_id=fw_id)` — firewall actions

**Proxy / DNS** — scoped to `proxy_id` — try `src_ip`, `client_ip`, `srcip`:
- `search_terms(field="dst_domain",  query='src_ip:"<ip>" OR client_ip:"<ip>"', range_seconds=N, size=20, stream_id=proxy_id)` — domains accessed
- `search_terms(field="http_status", query='src_ip:"<ip>" OR client_ip:"<ip>"', range_seconds=N, size=10, stream_id=proxy_id)` — HTTP status codes

**Timeline** — scoped to `fw_id` (proxy_id as fallback):
- `search_histogram(query='srcip:"<ip>" OR dstip:"<ip>" OR src_ip:"<ip>" OR dst_ip:"<ip>"', range_seconds=N, interval=<auto>, stream_id=fw_id)` — activity over time (minute if ≤1h, hour if ≤24h, day otherwise)

**Recent raw events** — scoped to `fw_id`:
- `search_relative(query='srcip:"<ip>" OR dstip:"<ip>"', range_seconds=N, limit=15, fields="timestamp,srcip,dstip,dport,action,srcuser,dst_domain", stream_id=fw_id)`

**Alerts** (no stream filter — search all):
- `search_events(query="<ip>", timerange_from=N)`

**IRIS**:
- `list_cases()` — scan case titles and descriptions for this IP

---

### Hash investigation

Build a compound query:
```
hash_query = 'hash:"<hash>" OR md5:"<hash>" OR sha256:"<hash>" OR sha1:"<hash>" OR file_hash:"<hash>" OR FileHash:"<hash>"'
```

All queries scoped to `edr_id`. Run **in parallel**:
- `search_terms(field="hostname",       query=hash_query, range_seconds=N, size=20, stream_id=edr_id)`
- `search_terms(field="username",       query=hash_query, range_seconds=N, size=20, stream_id=edr_id)`
- `search_terms(field="process_name",   query=hash_query, range_seconds=N, size=10, stream_id=edr_id)`
- `search_terms(field="parent_process", query=hash_query, range_seconds=N, size=10, stream_id=edr_id)`
- `search_terms(field="process_path",   query=hash_query, range_seconds=N, size=10, stream_id=edr_id)`
- `search_histogram(query=hash_query, range_seconds=N, interval=<auto>, stream_id=edr_id)`
- `search_relative(query=hash_query, range_seconds=N, limit=20, fields="timestamp,hostname,username,process_name,parent_process,process_path,command_line", stream_id=edr_id)`
- `search_relative(query=hash_query, range_seconds=N, limit=10, fields="timestamp,hostname,dst_ip,dport,protocol", stream_id=edr_id)` — network connections
- `search_events(query="<hash>", timerange_from=N)` — alerts (no stream filter)
- `list_cases()` — IRIS lookup

---

### Process / file name investigation

```
proc_query = 'process_name:"<name>" OR process:"<name>" OR cmd:"<name>" OR OriginalFileName:"<name>" OR Image:"<name>"'
```

All queries scoped to `edr_id`. Run **in parallel**:
- `search_terms(field="hostname",       query=proc_query, range_seconds=N, size=20, stream_id=edr_id)`
- `search_terms(field="username",       query=proc_query, range_seconds=N, size=20, stream_id=edr_id)`
- `search_terms(field="parent_process", query=proc_query, range_seconds=N, size=10, stream_id=edr_id)`
- `search_terms(field="process_path",   query=proc_query, range_seconds=N, size=10, stream_id=edr_id)`
- `search_terms(field="hash",           query=proc_query, range_seconds=N, size=10, stream_id=edr_id)`
- `search_histogram(query=proc_query, range_seconds=N, interval=<auto>, stream_id=edr_id)`
- `search_relative(query=proc_query, range_seconds=N, limit=20, fields="timestamp,hostname,username,process_name,parent_process,process_path,command_line,hash", stream_id=edr_id)`
- `search_events(query="<name>", timerange_from=N)` — alerts (no stream filter)
- `list_cases()` — IRIS lookup

---

### Generic string investigation

No stream scoping — search all streams (indicator could appear anywhere):
- `search_relative(query='"<indicator>"', range_seconds=N, limit=50)`
- `search_terms(field="source",           query='"<indicator>"', range_seconds=N, size=20)`
- `search_terms(field="application_name", query='"<indicator>"', range_seconds=N, size=10)`
- `search_histogram(query='"<indicator>"', range_seconds=N, interval=<auto>)`
- `search_events(query="<indicator>", timerange_from=N)`
- `list_cases()` — IRIS lookup

---

## Phase 3 — Apply analyst heuristics (silently, before writing the report)

### IP heuristics

| Signal | Interpretation |
|---|---|
| Destination ports 3333, 4444, 5555, 1337, 14444, 4899 | Likely C2 or crypto mining — flag as high risk |
| Port 22 to many unique destination IPs | Potential SSH scanner |
| Port 443/80 at high, regular frequency to single external IP | HTTPS C2 beaconing |
| Histogram shows consistent interval (every N min/hours) | Beaconing pattern — strongest C2 signal |
| Action = DENY but count > 100 | Blocked but persistent — still investigate |
| Activity concentrated between 22:00–06:00 | Off-hours — suspicious for workstations |
| Internal RFC1918 source → external non-standard ports | Likely infected workstation |
| Many unique source IPs → this destination | Host under scan, or public-facing server |

### Hash / process heuristics

| Signal | Interpretation |
|---|---|
| Same hash on 3+ hosts | Spreading / lateral movement — escalate immediately |
| Running as SYSTEM or Administrator | Privilege abuse or malware with elevated rights |
| Execution path contains `\Temp\`, `\AppData\`, `\Public\`, `\Downloads\` | Staged payload / evasion |
| Parent is `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `regsvr32.exe` | Script-based execution chain — high suspicion |
| Same hash on one host multiple times | Persistence mechanism |
| Process makes outbound 443 connections | HTTPS C2 — cross-reference destination IPs |
| Process name matches known LOLBin (`rundll32`, `msiexec`, `certutil`, `bitsadmin`) | Living-off-the-land technique |

---

## Phase 4 — Auto-pivot (maximum 1 level, highest-risk lead only)

Pick the single most suspicious new lead found in Phase 2/3 and investigate it.
Do not pivot more than once. Note other leads as "further investigation recommended."

| Situation | Auto-pivot action |
|---|---|
| IP investigation reveals a specific **username** | `search_relative(query='username:"<user>" OR srcuser:"<user>"', range_seconds=N, limit=30, fields="timestamp,srcip,dstip,dport,action,hostname", stream_id=fw_id)` — summarise in 2–3 sentences |
| IP investigation reveals **suspicious destination domain** (DGA-like, new TLD, typosquat) | `search_relative(query='dst_domain:"<domain>"', range_seconds=N, limit=20, stream_id=proxy_id)` — find all hosts that contacted it |
| Hash on **3+ hosts** | Take the earliest-hit host → `search_relative(query='hostname:"<host>"', range_seconds=3600, limit=30, fields="timestamp,process_name,parent_process,username,command_line", stream_id=edr_id)` in ±1h around first detection |
| Process shows **unusual parent** | Re-run process investigation on the parent name, scoped to `edr_id` |

---

## Phase 5 — Write the report

Defang all external IPs and domains (replace `.` with `[.]`).

```
**Indicator:** `<indicator>` | **Type:** <IPv4 / MD5 / SHA256 / Process / String> | **Period:** <from> → <to>
**Streams:** firewall=<title or "all">, proxy=<title or "all">, edr=<title or "all">

**Summary**
[2–3 sentences: what this indicator is, what it appears to be doing, overall risk read]

---

### Traffic Profile   ← (IP only)
**Outbound** — N total events as source
| Destination IP | Count |   | Top Port | Count |   | Action | Count |   | User | Count |

**Inbound** — N total events as destination
| Source IP | Count |   | Action | Count |

**Proxy / DNS activity**
| Domain accessed | Count |

---

### Execution Profile   ← (hash / process only)
**Scope** — N unique hosts, N unique users
| Host | Count |   | User | Count |   | Process name | Count |

**Execution context**
| Parent process | Count |   | Execution path | Count |

**Network connections from process**
| Destination IP | Port | Count |

---

### Activity Timeline
[Summarise the histogram: sustained vs spike, peak time window, first/last event]

---

### Alerts
[Triggered alert definition names and counts, or "None found"]

---

### IRIS Cases
[Matching open cases by ID and title, or "No matching cases found"]

---

### Auto-Pivot: <indicator pivoted to>
[2–3 sentences on findings. Omit if no pivot was performed.]

---

### Assessment

| Field | Value |
|---|---|
| **Risk Tier** | T1 — Critical / T2 — High / T3 — Medium / T4 — Low / T5 — Benign |
| **Behaviour** | [Plain-language description] |
| **Confidence** | High / Medium / Low |
| **MITRE ATT&CK** | [Technique ID + name, or "Not mapped"] |
| **Recommended action** | Block at firewall / Escalate to T2 / Open IRIS case / Monitor / Close as benign |
```
