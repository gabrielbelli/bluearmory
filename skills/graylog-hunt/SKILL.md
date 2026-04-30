---
name: graylog-hunt
description: >
  SOC threat hunt for any indicator (IP, CIDR, username, domain, hostname, hash,
  process name, or free text) against a Graylog 6.x instance. Discovers stream
  roles dynamically by probing the program field, routes queries per log type,
  applies SOC heuristics, auto-pivots on the highest-risk lead, and produces a
  structured risk-tiered report with MITRE ATT&CK mapping.
---

Hunt for: $ARGUMENTS

---

## Argument parsing

Extract optional time window suffix from `$ARGUMENTS`:
- Pattern: `last <N> <unit>` — e.g. `last 7 days`, `last 6h`, `last 24 hours`
- Units: `h`/`hour`/`hours` → N × 3600; `d`/`day`/`days` → N × 86400; `w`/`week`/`weeks` → N × 604800; bare integer → seconds
- Default when no suffix: `last 24 hours` → `range_seconds = 86400`

Store the cleaned indicator (with the time suffix removed) as `RAW_INDICATOR`.
Store the computed seconds as `RANGE`.

---

## Phase 0 — Classify the indicator

Classify `RAW_INDICATOR` before making any MCP calls.

| Pattern | Type |
|---|---|
| `\d{1,3}(\.\d{1,3}){3}` with no `/` | `IPv4` |
| `\d{1,3}(\.\d{1,3}){3}/\d{1,2}` | `CIDR` — expand to `[lo TO hi]` Lucene range |
| Exactly 32 hex chars | `MD5` |
| Exactly 40 hex chars | `SHA1` |
| Exactly 64 hex chars | `SHA256` |
| Contains `\` or matches `WORD\WORD` | `Username` — also keep domain prefix for exact search |
| Ends in `.exe .dll .ps1 .bat .vbs .sh .py .elf` | `ProcessName` |
| Matches `^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` and no spaces | `Domain` |
| Short alphanumeric (≤ 20 chars, no spaces, no special chars) | `Username` — ambiguous, also search as hostname |
| Anything else | `FreeText` — wrap in double-quotes for Lucene |

For `CIDR`: compute the network address and broadcast address from the prefix length, then build:
`srcip:[<lo> TO <hi>] OR src_ip:[<lo> TO <hi>] OR src:[<lo> TO <hi>]`

Print the classification result before proceeding.

---

## Phase 1 — Stream discovery and role mapping

**Step 1.1** — Call `list_streams()` once.

**Filter out** any stream where:
- `title.lower() == "all messages"`, OR
- `title.lower() == "all events"`, OR
- `title.lower() == "all system events"`, OR
- `disabled == true`

These are Graylog system streams. Including them in scoped queries would duplicate results or expose cross-tenant data.

**Step 1.2** — Probe each remaining stream in parallel. For every stream, call:

```
aggregate_messages(
    groupings=[{"field": "program", "limit": 10}],
    query="*",
    range_seconds=RANGE,
    streams=["<stream_id>"],
    timeout_ms=8000
)
```

Run all probes simultaneously in a single message (multiple tool calls).

**Step 1.3** — Assign roles based on the top `program` values returned:

| `program` value | Role |
|---|---|
| `suricata` | `IDS` |
| `paloalto` | `NGFW` |
| `proxy` | `PROXY` |
| `waf` or `nginx` | `WAF` |
| `openvpn*`, `ppp*`, `strongswan*` | `VPN` |
| anything else with count > 0 | `OTHER` |

A stream gets every role whose `program` value appears in its top-10 terms. A stream with both `suricata` and `nginx` is both `IDS` and `WAF`.

If a stream probe returns empty terms (no `program` field, or no messages in the time window), fall back to keyword matching in the stream's `title` and `description`:
- `suricata`, `ids`, `ips` → `IDS`
- `paloalto`, `palo`, `ngfw`, `firewall`, `fw` → `NGFW`
- `proxy`, `squid`, `zscaler`, `bluecoat` → `PROXY`
- `waf`, `modsec`, `nginx` → `WAF`
- `vpn`, `openvpn`, `ssl vpn` → `VPN`

Build these stream ID lists (Python lists of ID strings):
```
IDS_IDS    = list of IDs of all IDS-role streams
NGFW_IDS   = list of IDs of all NGFW-role streams
PROXY_IDS  = list of IDs of all PROXY-role streams
WAF_IDS    = list of IDs of all WAF-role streams
ALL_IDS    = list of IDs of ALL classified streams (IDS + NGFW + PROXY + WAF + VPN + OTHER)
```

Print the mapping before Phase 2:
```
Stream roles resolved:
  IDS:   <comma-separated stream titles>
  NGFW:  <comma-separated stream titles>
  PROXY: <comma-separated stream titles>
  WAF:   <comma-separated stream titles>
  VPN:   <comma-separated stream titles>
  OTHER: <comma-separated stream titles>
```

If a role has no streams, skip all queries for that role. Do not fall back to unscoped searches.

---

## Phase 2 — Query execution

### Field fallback rule

If a query returns `total == 0` **and** `rows` (or `messages`) is empty, retry with the next field name variant. Maximum 2 retries per field family. If all variants return 0, record "no data" for that dimension and continue.

Field fallback tables:

| Family | Try in order |
|---|---|
| Source IP | `srcip`, `src_ip`, `src` |
| Destination IP | `dstip`, `dst_ip`, `dst` |
| Destination port | `dst_port`, `dport`, `dest_port` |
| Source port | `src_port`, `sport` |
| Username | `srcuser`, `username`, `user` |
| Action | `action`, `alert_action` |
| Alert signature | `alert_signature`, `alert_category` |

### Parallelism rules

1. All Phase 1 stream probes: fully parallel.
2. All queries within a single log-type block (all IDS queries, all NGFW queries, etc.): fully parallel.
3. All log-type blocks themselves: fully parallel — start IDS, NGFW, PROXY, and WAF blocks simultaneously.
4. Field fallback retries: sequential within a retry chain.
5. Alert events and IRIS calls: parallel with Phase 2 blocks.

---

### 2A — IPv4 investigation

Build these query strings:
```
SRC_Q = 'srcip:"<ip>" OR src_ip:"<ip>" OR src:"<ip>"'
DST_Q = 'dstip:"<ip>" OR dst_ip:"<ip>" OR dst:"<ip>"'
ANY_Q = SRC_Q + " OR " + DST_Q
```

**IDS block** (skip if IDS_IDS is empty) — all in parallel:
```
aggregate_messages(groupings=[{"field":"alert_signature","limit":20}],                     query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"alert_category","limit":10}],                      query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"alert_severity","limit":5}],                       query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"alert_action","limit":5}],                         query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"dstip","limit":20}],                               query=SRC_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"dst_port","limit":20}],                            query=SRC_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"app_proto","limit":10}],                           query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"alert_metadata_mitre_tactic_name","limit":10}],    query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"alert_metadata_mitre_technique_name","limit":10}], query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"timestamp","granularity":"auto"}],                  query=ANY_Q, range_seconds=RANGE, streams=IDS_IDS)
search_messages(query=ANY_Q, range_seconds=RANGE, limit=15,
                fields=["timestamp","srcip","dstip","dst_port","alert_signature","alert_severity","alert_action","alert_category","app_proto","direction"],
                streams=IDS_IDS)
```

**NGFW block** (skip if NGFW_IDS is empty) — all in parallel:
```
aggregate_messages(groupings=[{"field":"action","limit":10}],       query=SRC_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"dstip","limit":20}],        query=SRC_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"dport","limit":20}],        query=SRC_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"app","limit":15}],          query=ANY_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"srcuser","limit":10}],      query=SRC_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"rule","limit":10}],         query=ANY_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"thr_category","limit":10}], query=ANY_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"subtype","limit":10}],      query=ANY_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"severity","limit":5}],      query=ANY_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"srcip","limit":20}],        query=DST_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"timestamp","granularity":"auto"}],  query=ANY_Q, range_seconds=RANGE, streams=NGFW_IDS)
search_messages(query=ANY_Q, range_seconds=RANGE, limit=15,
                fields=["timestamp","srcip","dstip","dport","sport","action","app","rule","srcuser","type","subtype","severity","thr_category","srcloc","dstloc","from","to"],
                streams=NGFW_IDS)
```

**PROXY block** (skip if PROXY_IDS is empty) — all in parallel:
```
aggregate_messages(groupings=[{"field":"type","limit":10}],     query=SRC_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"risk","limit":5}],      query=SRC_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"response","limit":10}], query=SRC_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"agent","limit":10}],    query=SRC_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"timestamp","granularity":"auto"}], query=SRC_Q, range_seconds=RANGE, streams=PROXY_IDS)
search_messages(query=SRC_Q, range_seconds=RANGE, limit=15,
                fields=["timestamp","srcip","uri","type","risk","response","agent","source_servico"],
                streams=PROXY_IDS)
```

**WAF block** (skip if WAF_IDS is empty) — all in parallel:
```
aggregate_messages(groupings=[{"field":"action","limit":5}],                    query=DST_Q, range_seconds=RANGE, streams=WAF_IDS)
aggregate_messages(groupings=[{"field":"messages_details_ruleId","limit":20}],  query=DST_Q, range_seconds=RANGE, streams=WAF_IDS)
aggregate_messages(groupings=[{"field":"messages_details_severity","limit":5}], query=DST_Q, range_seconds=RANGE, streams=WAF_IDS)
aggregate_messages(groupings=[{"field":"http_user_agent","limit":10}],          query=DST_Q, range_seconds=RANGE, streams=WAF_IDS)
aggregate_messages(groupings=[{"field":"http_x_forwarded_for","limit":10}],     query=DST_Q, range_seconds=RANGE, streams=WAF_IDS)
search_messages(query=DST_Q, range_seconds=RANGE, limit=15,
                fields=["timestamp","host","host_ip","action","messages_details_ruleId","messages_details_severity","messages_details_match","http_user_agent","http_x_forwarded_for","request"],
                streams=WAF_IDS)
```

**Events** (no stream filter):
```
search_events(query="<ip>", timerange_from=RANGE)
```

---

### 2B — CIDR investigation

Compute `LO` and `HI` addresses from the prefix length. Build:
```
SRC_Q = 'srcip:[<LO> TO <HI>] OR src_ip:[<LO> TO <HI>] OR src:[<LO> TO <HI>]'
DST_Q = 'dstip:[<LO> TO <HI>] OR dst_ip:[<LO> TO <HI>] OR dst:[<LO> TO <HI>]'
ANY_Q = SRC_Q + " OR " + DST_Q
```

Run the same IDS, NGFW, PROXY, WAF blocks as 2A (substituting the range queries).

Add these to identify the most active individual IPs within the range (run in parallel with 2A blocks):
```
aggregate_messages(groupings=[{"field":"srcip","limit":20}], query=SRC_Q, range_seconds=RANGE, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"dstip","limit":20}], query=DST_Q, range_seconds=RANGE, streams=ALL_IDS)
```

---

### 2C — Username investigation

```
USER_Q = 'srcuser:"<user>" OR username:"<user>" OR user:"<user>"'
```
If the original input had a domain prefix (`DOMAIN\user`), also append:
`OR srcuser:"DOMAIN\\<user>"`

**NGFW block** — all in parallel:
```
aggregate_messages(groupings=[{"field":"srcip","limit":20}],  query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"dstip","limit":20}],  query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"dport","limit":20}],  query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"action","limit":10}], query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"app","limit":10}],    query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"rule","limit":10}],   query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"timestamp","granularity":"auto"}], query=USER_Q, range_seconds=RANGE, streams=NGFW_IDS)
search_messages(query=USER_Q, range_seconds=RANGE, limit=20,
                fields=["timestamp","srcip","dstip","dport","action","app","rule","srcuser","type","subtype","severity"],
                streams=NGFW_IDS)
```

**IDS block** — all in parallel:
```
aggregate_messages(groupings=[{"field":"alert_signature","limit":20}], query=USER_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"srcip","limit":20}],           query=USER_Q, range_seconds=RANGE, streams=IDS_IDS)
search_messages(query=USER_Q, range_seconds=RANGE, limit=10,
                fields=["timestamp","srcip","dstip","dst_port","alert_signature","alert_severity"],
                streams=IDS_IDS)
```

**PROXY block** — all in parallel:
```
aggregate_messages(groupings=[{"field":"uri","limit":20}],      query=USER_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"type","limit":10}],     query=USER_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"risk","limit":5}],      query=USER_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"response","limit":10}], query=USER_Q, range_seconds=RANGE, streams=PROXY_IDS)
```

**Events** (no filter):
```
search_events(query="<user>", timerange_from=RANGE)
```

---

### 2D — Domain investigation

```
DOMAIN_Q = 'misc:"<domain>" OR uri:"<domain>" OR host:"<domain>" OR dst_domain:"<domain>"'
```

**PROXY block** — all in parallel:
```
aggregate_messages(groupings=[{"field":"srcip","limit":20}],    query=DOMAIN_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"risk","limit":5}],      query=DOMAIN_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"response","limit":10}], query=DOMAIN_Q, range_seconds=RANGE, streams=PROXY_IDS)
aggregate_messages(groupings=[{"field":"timestamp","granularity":"auto"}], query=DOMAIN_Q, range_seconds=RANGE, streams=PROXY_IDS)
search_messages(query=DOMAIN_Q, range_seconds=RANGE, limit=20,
                fields=["timestamp","srcip","uri","type","risk","response","agent"],
                streams=PROXY_IDS)
```

**NGFW block** — all in parallel:
```
aggregate_messages(groupings=[{"field":"srcip","limit":20}],             query=DOMAIN_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"action","limit":10}],            query=DOMAIN_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"url_category_list","limit":10}], query=DOMAIN_Q, range_seconds=RANGE, streams=NGFW_IDS)
aggregate_messages(groupings=[{"field":"srcuser","limit":10}],           query=DOMAIN_Q, range_seconds=RANGE, streams=NGFW_IDS)
search_messages(query=DOMAIN_Q, range_seconds=RANGE, limit=15,
                fields=["timestamp","srcip","misc","action","url_category_list","type","srcuser","severity"],
                streams=NGFW_IDS)
```

**WAF block** — all in parallel:
```
aggregate_messages(groupings=[{"field":"http_x_forwarded_for","limit":10}],    query=DOMAIN_Q, range_seconds=RANGE, streams=WAF_IDS)
aggregate_messages(groupings=[{"field":"messages_details_ruleId","limit":10}], query=DOMAIN_Q, range_seconds=RANGE, streams=WAF_IDS)
search_messages(query=DOMAIN_Q, range_seconds=RANGE, limit=10,
                fields=["timestamp","host","host_ip","action","messages_details_ruleId","http_user_agent"],
                streams=WAF_IDS)
```

**Events**:
```
search_events(query="<domain>", timerange_from=RANGE)
```

---

### 2E — Hash investigation (MD5 / SHA1 / SHA256)

```
HASH_Q = '"<hash>"'
```

**IDS block** (suricata logs file metadata with hashes) — all in parallel:
```
aggregate_messages(groupings=[{"field":"srcip","limit":20}], query=HASH_Q, range_seconds=RANGE, streams=IDS_IDS)
aggregate_messages(groupings=[{"field":"dstip","limit":20}], query=HASH_Q, range_seconds=RANGE, streams=IDS_IDS)
search_messages(query=HASH_Q, range_seconds=RANGE, limit=20,
                fields=["timestamp","srcip","dstip","dst_port","files","event_type","app_proto"],
                streams=IDS_IDS)
```

**Broad sweep across all classified streams**:
```
search_messages(query=HASH_Q, range_seconds=RANGE, limit=30, streams=ALL_IDS)
search_events(query="<hash>", timerange_from=RANGE)
```

---

### 2F — ProcessName investigation

```
PROC_Q = '"<name>"'
```

```
search_messages(query=PROC_Q, range_seconds=RANGE, limit=50, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"srcip","limit":20}],           query=PROC_Q, range_seconds=RANGE, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"alert_signature","limit":10}], query=PROC_Q, range_seconds=RANGE, streams=IDS_IDS)
search_events(query="<name>", timerange_from=RANGE)
```

---

### 2G — FreeText investigation

```
FREE_Q = '"<RAW_INDICATOR>"'
```

No stream scoping — uses ALL_IDS:
```
search_messages(query=FREE_Q, range_seconds=RANGE, limit=50, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"program","limit":10}], query=FREE_Q, range_seconds=RANGE, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"srcip","limit":20}],   query=FREE_Q, range_seconds=RANGE, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"dstip","limit":20}],   query=FREE_Q, range_seconds=RANGE, streams=ALL_IDS)
aggregate_messages(groupings=[{"field":"timestamp","granularity":"auto"}], query=FREE_Q, range_seconds=RANGE, streams=ALL_IDS)
search_events(query="<RAW_INDICATOR>", timerange_from=RANGE)
```

---

## Phase 3 — SOC heuristics (silent)

Apply after Phase 2. Do not output intermediate results. Use findings only to drive Phase 4 and the risk tier in Phase 5.

### IP / CIDR

| Signal | Risk contribution |
|---|---|
| IDS `alert_severity` term `1` count > 0 | Critical |
| IDS `alert_severity` term `2` count > 0 | High |
| IDS has alerts but `alert_action` = `allowed` only (no `blocked`) | High — active unblocked traffic |
| IDS MITRE tactic contains `Command_And_Control` | Critical |
| IDS MITRE tactic contains `Lateral_Movement` or `Exfiltration` | Critical |
| Histogram bucket counts nearly equal (variance < 20 % of mean) and N ≥ 6 buckets | High — beaconing pattern |
| NGFW `thr_category` contains `code-execution` | Critical |
| NGFW `thr_category` contains `dos` or `brute-force` | High |
| NGFW `action` = `drop`/`drop-packet`/`reset-*` with count > 500 | Medium — blocked but persistent |
| NGFW `action` = `alert` with `type=THREAT` and no drop action | High — NGFW alerting but not blocking |
| Proxy `risk` = `High Risk` terms present | High |
| Proxy `risk` = `Medium Risk` and `response=200` | Medium — successful access |
| WAF `action` = `detected` only (no `blocked`) | Medium — WAF not in blocking mode |
| WAF `messages_details_ruleId` starts with `932`, `933`, `934` (RCE) | Critical |
| WAF `messages_details_ruleId` starts with `942` (SQLi) | High |
| WAF `messages_details_ruleId` starts with `941` (XSS) | High |
| IP appears in `*_reserved_ip=true` fields | Context only (internal IP) |
| `dport` / `dst_port` includes 3333, 4444, 5555, 1337, 14444, 6667, 4899 | High — common C2/RAT ports |
| `dport` 22 with > 10 unique `dstip` values | High — SSH scanning |
| NGFW `type=URL` hits only, `srcuser` present | Low — routine user browsing |

### Username

| Signal | Risk contribution |
|---|---|
| Same username associated with > 3 unique source IPs in NGFW | High — credential sharing or lateral movement |
| Username associated with `type=THREAT` in NGFW | High |
| Username browses `High Risk` proxy categories | Medium |

### Domain

| Signal | Risk contribution |
|---|---|
| Proxy `risk` = `High Risk` | High |
| > 10 unique source IPs accessing domain | High — potential malware callback |
| WAF `action=blocked` from this domain as origin | Medium |
| NGFW `url_category_list` contains `malware`, `phishing`, or `botnet` | Critical |
| Domain name matches DGA pattern (10+ consecutive random-looking chars before first dot, or unusual TLD like `.xyz`, `.top`, `.tk`, `.pw`) | High |

---

## Phase 4 — Auto-pivot (maximum 1 level)

Identify the single most suspicious new lead found in Phase 2/3. Priority order:

1. If MITRE tactic is Critical and a specific `dstip` (not the indicator itself) is the top IDS term → pivot to that IP.
2. If a username was found as a top `srcuser` term associated with `type=THREAT` events → pivot to that username.
3. If a `misc` or `uri` domain from NGFW/Proxy is DGA-like or has an unusual TLD → pivot to that domain.
4. If a hash appears in IDS file events across multiple source IPs → pivot to the most active source IP.

Pivot: run the appropriate Phase 2 block(s) for the pivot indicator type, with the same `RANGE` and same stream IDs. Summarise findings in 3 sentences. List remaining leads as "further investigation recommended."

Do not pivot again from the pivot result.

---

## Phase 5 — Write the report

**Defanging rule:** replace every `.` in external (non-RFC1918) IPs and FQDNs with `[.]`. Do not defang RFC1918 addresses (`10.x`, `172.16–31.x`, `192.168.x`).

---

```
**Indicator:** `<RAW_INDICATOR>` | **Type:** <type> | **Period:** last <N> h/d
**Streams searched:** IDS=<titles or "none">, NGFW=<titles or "none">, PROXY=<titles or "none">, WAF=<titles or "none">

## Summary
[2–4 sentences: what the indicator is, what behaviour was observed, overall risk read]

---

## IDS Findings
**Total alerts:** N | **Blocked:** N | **Allowed (active):** N

Top signatures:
| Signature | Count | Severity |
|---|---|---|

MITRE coverage:
| Tactic | Technique | Count |
|---|---|---|

Top peer IPs:
| Direction | IP | Count |
|---|---|---|
| As source → dest | x[.]x[.]x[.]x | N |
| As dest ← src | x[.]x[.]x[.]x | N |

Top protocols: | app_proto | Count |

Sample events (up to 5):
`[timestamp] srcip → dstip:port | signature | action`

---

## NGFW Findings
**Total events:** N | **THREAT:** N | **TRAFFIC:** N | **URL:** N

Actions: | Action | Count |

Top applications: | app | Count |

Threat categories: | thr_category | Count |

Rules triggered: | rule | Count |

Users seen: | srcuser | Count |

Sample events (up to 5):
`[timestamp] srcip → dstip:dport | action | app | type/subtype | severity`

---

## Proxy Findings
**Total requests:** N

| URL category | Count | | Risk level | Count | | HTTP status | Count |

Top user agents: | agent | Count |

Sample URLs (up to 5):
`[timestamp] srcip → uri | risk | response`

---

## WAF Findings
**Total events:** N | **Blocked:** N | **Detected:** N

| OWASP Rule ID | Count | Severity | Match |

Attacker IPs (X-Forwarded-For): | ip | Count |

---

## Alert Events
[Triggered Graylog alert definition names and counts, or "None found"]

---

## Activity Timeline
[Histogram narrative: sustained / spike / periodic / one-shot. Peak time window. First seen. Last seen.
State explicitly if a regular-interval beaconing pattern was detected.]

---

## Auto-Pivot: <pivot indicator>
[3 sentences on findings. Omit this section entirely if no pivot was performed.]

---

## Assessment

| Field | Value |
|---|---|
| **Risk Tier** | T1 — Critical / T2 — High / T3 — Medium / T4 — Low / T5 — Benign |
| **Primary behaviour** | [Plain-language description] |
| **Confidence** | High / Medium / Low |
| **MITRE ATT&CK** | Tactic: Technique (TXXXX) — or "Not mapped" |
| **Data sources hit** | IDS / NGFW / Proxy / WAF / Events |
| **Recommended action** | Block at NGFW / Escalate to T2 / Open IRIS case / Monitor / Close as benign |
| **Proposed IRIS severity** | Critical / High / Medium / Low — if opening a case |
```
