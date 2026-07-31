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

> **SOC note:** these tools return log/case data that can contain the literal value of a
> configured secret (credential-leak cases, captured auth traffic), which the gateway's
> default guard blocks (`MCP error 0: a secret is being returned`). You'll probably need to
> launch the gateway with `--block-secrets=false`. Unfortunate, but expected.

### Turning off the secret guard

The flag goes on the gateway launch command in your MCP client's config. For Claude Code,
add it to the `MCP_DOCKER` server args (`.mcp.json` in the project, or `~/.claude.json`):

```json
{
  "mcpServers": {
    "MCP_DOCKER": {
      "command": "docker",
      "args": ["mcp", "gateway", "run", "--profile", "blueteam", "--block-secrets=false"]
    }
  }
}
```

Restart the client. Verify with `ps aux | grep 'gateway run'` — it should show
`--block-secrets=false`.

> **Gotcha:** if the same server is defined in both `~/.claude.json` (local scope) and
> `.mcp.json`, the local one wins — put the flag there, or remove the duplicate.

### Updating to the latest tools

**Nothing updates automatically.** The gateway runs each server with `--pull never` and
serves a **frozen snapshot** of its tools, so a new image or catalog is ignored until you
refresh by hand. Do all four steps (using `graylog` as the example — swap in your server
and profile):

```bash
# 1. pull the new image — the gateway only ever uses what you have pulled locally
docker pull ghcr.io/gabrielbelli/graylog-mcp:latest

# 2. pull the updated catalog  (note: it is "pull", there is no "import")
docker mcp catalog pull ghcr.io/gabrielbelli/bluearmory:latest

# 3. re-add the server to re-snapshot its tools from the new catalog
docker mcp profile server add <profile> \
  --server catalog://ghcr.io/gabrielbelli/bluearmory:latest/graylog

# 4. re-enter the server's config — step 3 WIPES it (URL, username, etc.)
docker mcp profile config <profile> --set graylog.url=https://your-graylog
#    (verify: docker mcp profile config <profile> --get-all)

# 5. restart the gateway: Docker Desktop → MCP Toolkit → toggle the server off/on
```

The two steps people miss:

- **Step 3 (re-snapshot).** The profile keeps a frozen copy of each server's tools from
  when you enabled it. Pulling a new catalog does nothing on its own — you must re-add the
  server. GUI equivalent: toggle the server off then on.
- **Step 4 (re-enter config).** Re-adding a server **clears its stored config**. If you
  skip this, the whole profile fails to activate (`Missing/invalid config: url`) and the
  gateway won't connect at all — not just that one server. Watch for stray spaces in the
  value; a leading space makes the URL fail as "missing protocol".

> Secrets (API tokens) survive step 3 — they're stored separately, so you only re-enter the
> non-secret config. Still seeing old behaviour after all five steps? Force a clean image:
> `docker image rm <image>:latest && docker pull <image>:latest`, then redo from step 2.

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
