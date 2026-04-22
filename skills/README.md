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
| [triage](triage/) | IOC triage — enrich, correlate, assess, recommend |
| [report](report/) | Structured incident report with MITRE ATT&CK mapping |
