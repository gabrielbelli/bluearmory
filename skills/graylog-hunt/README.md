# graylog-hunt skill

Autonomous SOC threat hunt for any indicator against a Graylog 6.x instance.

The skill drives Claude through a structured five-phase investigation workflow — stream discovery, parallel log-type queries, SOC heuristics, an auto-pivot on the top lead, and a risk-tiered report with MITRE ATT&CK mapping — with no hardcoded client names or stream IDs.

## Install

```sh
# From a local clone
./install-skill graylog-hunt

# Directly from GitHub
curl -sL https://raw.githubusercontent.com/gabrielbelli/bluearmory/master/install-skill | sh -s graylog-hunt
```

## Usage

### As a Claude Code skill

Invoke with any indicator. Optionally append a time window.

```
/graylog-hunt 192.168.1.105
/graylog-hunt 45.142.193.12 last 7 days
/graylog-hunt jdoe last 24 hours
/graylog-hunt evil.domain.com
/graylog-hunt 4d5f3b9a1c2e...   # SHA256
/graylog-hunt mimikatz last 3 days
```

Requires the `graylog` MCP server configured in your Claude Code environment (see [graylog-mcp](../../graylog-mcp/)).

### Via the MCP `hunt` tool

The `graylog-mcp` server exposes a `hunt` tool that runs this skill as an autonomous Claude sub-agent. Call it directly from any MCP client:

```
hunt("192.168.1.105")
hunt("jdoe", range_seconds=604800)
hunt("45.142.193.12 last 3 days")
```

The `hunt` tool requires `ANTHROPIC_API_KEY` in the server environment. See the [graylog-mcp README](../../graylog-mcp/README.md#with-the-hunt-tool-autonomous-investigation) for setup.

## How it works

### Phase 0 — Argument parsing & indicator classification

Extracts an optional `last N unit` time window from the input (default: last 24 hours). Classifies the cleaned indicator:

| Type | Pattern |
|---|---|
| `IPv4` | dotted-quad, no CIDR prefix |
| `CIDR` | dotted-quad with `/prefix` — expands to Lucene range query |
| `MD5 / SHA1 / SHA256` | 32 / 40 / 64 hex chars |
| `Username` | contains `\`, or short alphanumeric ≤ 20 chars |
| `Domain` | matches `hostname.tld`, no spaces |
| `ProcessName` | ends in `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.sh`, `.py`, `.elf` |
| `FreeText` | anything else — quoted for Lucene |

### Phase 1 — Dynamic stream discovery

1. Calls `list_streams()` and filters out Graylog system streams (`All messages`, `All events`, `All system events`) and disabled streams.
2. Probes every remaining stream **in parallel** with `aggregate_terms(field="program")` to discover what log sources each stream carries.
3. Assigns roles based on top `program` values: `IDS` (suricata), `NGFW` (paloalto), `PROXY` (proxy), `WAF` (waf/nginx), `VPN` (openvpn/strongswan), `OTHER`.
4. A stream can have multiple roles (e.g. suricata + nginx → IDS + WAF).
5. Falls back to keyword matching in stream title/description if the program probe returns empty.

No client names or stream IDs are hardcoded. The skill works on any Graylog instance.

### Phase 2 — Parallel query execution

All log-type blocks run simultaneously. Within each block, all field aggregations and message searches are also parallel.

| Indicator type | IDS | NGFW | Proxy | WAF |
|---|---|---|---|---|
| IPv4 | alert sigs, MITRE, peer IPs, ports, histogram | actions, apps, threats, users | categories, risk, user-agents | rule IDs, blocked/detected |
| CIDR | same as IPv4 + top active IPs within range | — | — | — |
| Username | alert sigs, source IPs | source IPs, apps, rules, actions | URIs, risk, categories | — |
| Domain | — | URL categories, source IPs | source IPs, risk, user-agents | rule IDs |
| Hash | file events across IDS | — | — | — |
| ProcessName / FreeText | broad sweep across all classified streams | — | — | — |

Field families use automatic fallback: e.g. `srcip` → `src_ip` → `src` if earlier variants return no results.

### Phase 3 — SOC heuristics (silent)

Applied silently after Phase 2 to compute the risk tier. Key signals:

- IDS severity 1 alerts with `alert_action=allowed` → Critical (active unblocked traffic)
- MITRE C2 or lateral movement tactics → Critical
- Histogram regularity (low variance across ≥ 6 buckets) → High (beaconing pattern)
- NGFW `thr_category=code-execution` → Critical
- Proxy `risk=High Risk` → High
- WAF RCE rule IDs (932xx/933xx/934xx) → Critical; SQLi (942xx) / XSS (941xx) → High
- C2/RAT common destination ports (4444, 1337, 6667, 4899, …) → High

### Phase 4 — Auto-pivot (one level)

Identifies the single highest-risk new lead from Phase 2/3 (C2 destination IP, threat-associated username, DGA domain, multi-source hash) and reruns the appropriate Phase 2 block for it. Does not recurse further.

### Phase 5 — Report

Structured Markdown report:

```
Indicator | Type | Period | Streams searched

## Summary
## IDS Findings       — sigs, MITRE table, peer IPs, sample events
## NGFW Findings      — actions, apps, threat categories, rules, users
## Proxy Findings     — URL categories, risk, user-agents, sample URLs
## WAF Findings       — OWASP rule IDs, blocked vs detected, attacker IPs
## Alert Events       — triggered Graylog alert definitions
## Activity Timeline  — narrative: sustained / spike / periodic / beaconing
## Auto-Pivot         — 3-sentence pivot finding (omitted if no pivot)
## Assessment         — Risk Tier (T1–T5), MITRE mapping, recommended action
```

External IPs and FQDNs are defanged (`1[.]2[.]3[.]4`). RFC1918 addresses are not defanged.

## Time window syntax

Append to any indicator:

```
last 6 hours       → 21600 seconds
last 24 hours      → 86400 seconds  (default)
last 7 days
last 2 weeks
```

When used via the `hunt` MCP tool, set `range_seconds` directly instead.

## Requirements

- Graylog MCP server configured and reachable (see [graylog-mcp](../../graylog-mcp/))
- Graylog 6.x (uses `views/search/sync` API; legacy `search_relative` etc. return 0 results on 6.x)
- For the `hunt` MCP tool: `ANTHROPIC_API_KEY` set in the server environment
