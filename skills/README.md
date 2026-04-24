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
| [investigate](investigate/) | Deep-dive on any indicator — IP, hash, process, or string. Auto-detects type, runs targeted Graylog queries, applies analyst heuristics, auto-pivots on top finding, produces a risk-tiered report with MITRE mapping. |
| [triage](triage/) | IOC triage — enrich, correlate, assess, recommend |
| [report](report/) | Structured incident report with MITRE ATT&CK mapping |
