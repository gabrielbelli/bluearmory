# Swiss

Aggregated threat intelligence MCP — fan-out queries across VirusTotal, AbuseIPDB, GreyNoise, Shodan, and 15+ other sources in a single call.

- **Source:** [bunnyiesart/swiss](https://github.com/bunnyiesart/swiss)
- **Image:** `ghcr.io/bunnyiesart/swiss:latest`
- **Transport:** stdio

## Setup

1. Create a config file at `~/.config/swiss/config.json` (see the repo for the full template).
2. Set API keys as environment variables (`SWISS_VIRUSTOTAL_API_KEY`, `SWISS_ABUSEIPDB_API_KEY`, etc.).

## MCP Config

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
