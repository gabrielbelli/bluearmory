# bluearmory

A collection of MCP servers and skills for blue team / SOC workflows.

## MCP Servers

Pre-built multi-arch images (amd64 + arm64) are published to GHCR.

| MCP | Description | Pull |
|---|---|---|
| [iris-mcp](iris-mcp/) | DFIR-IRIS case management | `docker pull ghcr.io/gabrielbelli/iris-mcp` |
| [graylog-mcp](graylog-mcp/) | Graylog SIEM log search and alerts | `docker pull ghcr.io/gabrielbelli/graylog-mcp` |

## Recommended External MCPs

### Swiss

Aggregated threat intelligence — fan-out queries across VirusTotal, AbuseIPDB, GreyNoise, Shodan, and 15+ other sources in a single call.

- **Source:** [bunnyiesart/swiss](https://github.com/bunnyiesart/swiss)
- **Image:** `ghcr.io/bunnyiesart/swiss:latest`

```json
{
  "mcpServers": {
    "swiss": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--network", "host",
        "-v", "${HOME}/.config/swiss/config.json:/config/swiss.json:ro",
        "-e", "SWISS_CONFIG_PATH=/config/swiss.json",
        "-e", "SWISS_VIRUSTOTAL_API_KEY",
        "-e", "SWISS_ABUSEIPDB_API_KEY",
        "-e", "SWISS_GREYNOISE_API_KEY",
        "-e", "SWISS_SHODAN_API_KEY",
        "ghcr.io/bunnyiesart/swiss:latest"
      ]
    }
  }
}
```

### Kali MCP

Official Kali Linux MCP server from OffSec — security testing and analysis tools.

- **Source:** [offsec/kali-mcp](https://github.com/offsec/kali-mcp)

```json
{
  "mcpServers": {
    "kali": {
      "command": "ssh",
      "args": ["-T", "-o", "RequestTTY=no", "kali", "mcp-server"]
    }
  }
}
```

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
