# bluearmory

A collection of MCP servers and skills for blue team / SOC workflows.

## MCP Servers

Each MCP is a standalone Docker image — build and run individually.

| MCP | Description | Build |
|---|---|---|
| [iris-mcp](iris-mcp/) | DFIR-IRIS case management | `docker build -t iris-mcp iris-mcp/` |
| [graylog-mcp](graylog-mcp/) | Graylog SIEM log search and alerts | `docker build -t graylog-mcp graylog-mcp/` |

## Catalog

External MCPs we recommend but don't build — see [catalog/](catalog/) for setup instructions.

| MCP | Source | Purpose |
|---|---|---|
| [Swiss](catalog/swiss.md) | [bunnyiesart/swiss](https://github.com/bunnyiesart/swiss) | Aggregated threat intelligence |
| [Kali](catalog/kali.md) | [offsec/kali-mcp](https://github.com/offsec/kali-mcp) | Kali Linux offensive/defensive tools |

## Skills

Claude Code skills for SOC workflows — install with the included script.

```sh
# From cloned repo
./install-skill triage

# Or directly from GitHub
curl -sL https://raw.githubusercontent.com/<you>/bluearmory/master/install-skill | sh -s triage
```

| Skill | Description |
|---|---|
| [triage](skills/triage/) | IOC triage workflow |
| [report](skills/report/) | Structured incident report generation |
