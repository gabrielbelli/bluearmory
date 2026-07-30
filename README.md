# bluearmory

A collection of MCP servers and skills for blue team / SOC workflows.

## Quick start: import the Docker MCP catalog

bluearmory ships as a Docker MCP **catalog** — one OCI reference gets you the
first-party servers pre-configured (name, secrets, config prompts, tool list).

**Docker Desktop** → MCP Toolkit → Catalogs → **Import catalog**, then paste:

```
ghcr.io/gabrielbelli/bluearmory:latest
```

**CLI:**

```bash
docker mcp catalog pull ghcr.io/gabrielbelli/bluearmory:latest
```

Then enable the servers you want and set their secrets (e.g. `graylog.api_token`)
in the MCP Toolkit UI or with `docker mcp secret set`.

> The catalog bundles the container-based servers ([`graylog`](graylog-mcp/),
> [`iris`](#mcp-iris), and [`swiss`](#swiss)). Kali is listed below as a manual entry
> only because it uses an SSH transport rather than a container image, which the
> catalog format doesn't express.

### Publishing the catalog (maintainers)

Server definitions live in [`catalog/`](catalog/) (one YAML per server, following the
[MCP server entry spec](https://github.com/docker/mcp-gateway/blob/main/docs/server-entry-spec.md)).
Build and push with:

```bash
./publish-catalog                        # → ghcr.io/gabrielbelli/bluearmory:latest
./publish-catalog ghcr.io/you/name:tag   # custom reference
```

CI ([`.github/workflows/catalog.yml`](.github/workflows/catalog.yml)) re-publishes
automatically on any change under `catalog/`. To add a server, drop a new
`catalog/<name>.yaml` in place — no other edits needed.

## MCP Servers

Pre-built multi-arch images (amd64 + arm64) are published to GHCR.

| MCP | Description | Pull |
|---|---|---|
| [graylog-mcp](graylog-mcp/) | Graylog SIEM log search and alerts | `docker pull ghcr.io/gabrielbelli/graylog-mcp` |

## Recommended External MCPs

### mcp-iris

Read-only MCP server for [DFIR-IRIS](https://dfir-iris.org/) — incident response case management. Curated ~10-tool set with hard limits, rate limiting, TTL cache for reference data, and timezone-aware filtering. Replaces the prior auto-generated iris-mcp in this repo.

- **Source:** [bunnyiesart/mcp-iris](https://github.com/bunnyiesart/mcp-iris)
- **Image:** `ghcr.io/bunnyiesart/mcp-iris:latest`

```json
{
  "mcpServers": {
    "iris": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "IRIS_URL",
        "-e", "IRIS_API_KEY",
        "ghcr.io/bunnyiesart/mcp-iris:latest"
      ]
    }
  }
}
```

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
        "run", "-i", "--rm",
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

> **Networking:** bridge networking (the default above) reaches public threat-intel
> APIs and any self-hosted back-end (MISP, Graylog, DFIR-IRIS, Wazuh) that lives on
> the web, another LAN host, or a VPN-reachable host — the container inherits the
> host's routes. Add `--network host` **only** if a back-end is bound to `127.0.0.1`
> on the same machine running the container; otherwise `--add-host name:ip` or a real
> DNS name is enough. Swiss is also in the [importable catalog](#quick-start-import-the-docker-mcp-catalog),
> which wires the common public API keys; use this manual entry for the full env
> surface (abuse.ch, IBM X-Force, Censys, and the self-hosted MISP/Graylog/IRIS/Wazuh back-ends).

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
