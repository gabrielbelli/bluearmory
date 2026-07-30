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
> [`iris`](#mcp-iris), [`opensearch`](#mcp-opensearch), and [`swiss`](#swiss)). Kali is listed below as a manual entry
> only because it uses an SSH transport rather than a container image, which the
> catalog format doesn't express.

### Use it in Claude Code (TL;DR)

The Docker MCP Toolkit runs one gateway that fans out to every server you enable —
so Claude Code connects **once** and gets all of them, secrets handled by Docker.

1. **Import** the catalog (above).
2. **Enable + configure** the servers you want in Docker Desktop → MCP Toolkit
   (toggle them on, fill in each server's secret/URL — e.g. `graylog.api_token`).
3. **Connect Claude Code** to the gateway:

   ```bash
   docker mcp client connect claude-code --global   # or drop --global for just this repo
   ```

That's it — the enabled servers show up as tools in Claude Code. No per-server
`docker run`, no hand-editing `mcp.json`, no secrets in your config. Add or remove
servers in the Toolkit and Claude Code picks up the change on restart.

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

### mcp-opensearch

Read-only MCP server for [OpenSearch](https://opensearch.org/) / OpenSearch Dashboards — search, aggregate, and explore log data for SOC workflows. 17 tools spanning connectivity, discovery, search (incl. PPL), and aggregations, with hard result caps.

- **Source:** [bunnyiesart/mcp-opensearch](https://github.com/bunnyiesart/mcp-opensearch)
- **Image:** `ghcr.io/bunnyiesart/mcp-opensearch:latest`

```json
{
  "mcpServers": {
    "opensearch": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "OPENSEARCH_DASHBOARDS_URL",
        "-e", "OPENSEARCH_USERNAME",
        "-e", "OPENSEARCH_PASSWORD",
        "ghcr.io/bunnyiesart/mcp-opensearch:latest"
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
> which wires the full key/secret + self-hosted-URL surface — the manual run above is
> mainly for the `config.json` fine-tuning described next.

#### Fine-tuning swiss with `config.json`

The catalog and the simple run above expose **secrets** (API keys) and **self-hosted URLs**
— that's all you need for the default fan-out, where every public source is on. For finer
control, swiss also reads a JSON config file (`enabled`, `favorite`, `url`, `verify_ssl`
per source, plus custom blacklists — see [swiss's config docs](https://github.com/bunnyiesart/swiss/blob/main/docs/configuration.md)):

| Field | What it does |
|---|---|
| `enabled` | Turn a source off entirely (e.g. skip a slow or noisy one) |
| `favorite` | Register a source as its **own dedicated tool** (e.g. `virustotal(ip)`) on top of the fan-out |
| `verify_ssl` | Disable TLS verification for a self-hosted back-end with a private cert |
| custom blacklists | Add your own IOC lists as a source |

> **API keys are never read from this file** — they are env-only (that's what the catalog
> secrets / `-e` flags are for). The file controls behaviour, not credentials.

To use it, mount it read-only and point `SWISS_CONFIG_PATH` at it — exactly the
`-v .../config.json:/config/swiss.json:ro` line in the run above. Catalog users get
the defaults out of the box; add the mount only when you want this level of control.
The file must be mode `600` or swiss refuses to start.

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
