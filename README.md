# bluearmory

A collection of MCP servers and skills for blue team / SOC workflows.

## MCP Servers

Pre-built multi-arch images (amd64 + arm64) are published to GHCR.

| MCP | Description | Pull |
|---|---|---|
| [iris-mcp](iris-mcp/) | DFIR-IRIS case management | `docker pull ghcr.io/gabrielbelli/iris-mcp` |
| [graylog-mcp](graylog-mcp/) | Graylog SIEM log search and alerts | `docker pull ghcr.io/gabrielbelli/graylog-mcp` |

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
curl -sL https://raw.githubusercontent.com/gabrielbelli/bluearmory/master/install-skill | sh -s triage
```

| Skill | Description |
|---|---|
| [triage](skills/triage/) | IOC triage workflow |
| [report](skills/report/) | Structured incident report generation |
