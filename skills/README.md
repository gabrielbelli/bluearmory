# Skills

Claude Code skills for SOC workflows.

## Install

```sh
# From cloned repo
./install-skill triage

# Or directly from GitHub
curl -sL https://raw.githubusercontent.com/<you>/bluearmory/master/install-skill | sh -s triage
```

This copies the skill into `.claude/skills/<name>/` in the current directory.

## Available Skills

| Skill | Description |
|---|---|
| [graylog-hunt](graylog-hunt/) | Autonomous threat hunt against Graylog 6.x — discovers stream roles dynamically by program field, routes queries per log type (IDS/NGFW/Proxy/WAF), applies SOC heuristics, auto-pivots on highest-risk lead, produces a risk-tiered report with MITRE mapping. Also available as a one-command MCP tool via `graylog-mcp`. |
| [investigate](investigate/) | Deep-dive on any indicator — IP, hash, process, or string. Auto-detects type, runs targeted Graylog queries, applies analyst heuristics, auto-pivots on top finding, produces a risk-tiered report with MITRE mapping. |
| [triage](triage/) | IOC triage — enrich, correlate, assess, recommend |
| [report](report/) | Structured incident report with MITRE ATT&CK mapping |
