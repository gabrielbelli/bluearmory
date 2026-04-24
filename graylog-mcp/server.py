"""Graylog MCP Server.

Wraps the Graylog REST API and exposes search, streams, alerts, aggregations,
pipelines, and dashboards as MCP tools for SOC workflows.
"""

import logging
import os

import httpx
from mcp.server.fastmcp import FastMCP
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logging.basicConfig(level=os.getenv("LOG_LEVEL", "WARNING"))
logger = logging.getLogger("graylog-mcp")

mcp = FastMCP("graylog")

GRAYLOG_URL = os.environ.get("GRAYLOG_URL", "http://localhost:9000")
GRAYLOG_API_TOKEN = os.environ.get("GRAYLOG_API_TOKEN", "")
GRAYLOG_VERIFY_SSL = os.getenv("GRAYLOG_VERIFY_SSL", "true").lower() != "false"

_http: httpx.Client | None = None


def _client() -> httpx.Client:
    global _http
    if _http is None:
        _http = httpx.Client(
            base_url=f"{GRAYLOG_URL}/api",
            auth=(GRAYLOG_API_TOKEN, "token"),
            headers={
                "Accept": "application/json",
                "X-Requested-By": "graylog-mcp",
                "User-Agent": "graylog-mcp/1.0",
            },
            verify=GRAYLOG_VERIFY_SSL,
            timeout=30,
        )
    return _http


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type(httpx.TransportError),
    reraise=True,
)
def _get(path: str, params: dict | None = None) -> dict:
    logger.debug("GET %s params=%s", path, params)
    r = _client().get(path, params=params)
    r.raise_for_status()
    return r.json()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type(httpx.TransportError),
    reraise=True,
)
def _post(path: str, body: dict) -> dict:
    logger.debug("POST %s", path)
    r = _client().post(path, json=body)
    r.raise_for_status()
    return r.json()


def _err(e: Exception) -> dict:
    if isinstance(e, httpx.HTTPStatusError):
        return {
            "error": f"HTTP {e.response.status_code}",
            "url": str(e.request.url),
            "detail": e.response.text[:500],
        }
    return {"error": type(e).__name__, "detail": str(e)}


# ── Search ─────────────────────────────────────────────────────────────────


@mcp.tool()
def search_relative(
    query: str,
    range_seconds: int = 300,
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with a relative time range.

    Args:
        query: Graylog search query (Lucene syntax)
        range_seconds: How far back to search in seconds (default: 300 = 5 minutes)
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = all)
        stream_id: Limit search to a specific stream ID (optional)
    """
    params: dict = {"query": query, "range": range_seconds, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/relative", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_absolute(
    query: str,
    from_time: str,
    to_time: str,
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with an absolute time range.

    Args:
        query: Graylog search query (Lucene syntax)
        from_time: Start time (ISO 8601, e.g. 2024-01-15T10:00:00.000Z)
        to_time: End time (ISO 8601)
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = all)
        stream_id: Limit search to a specific stream ID (optional)
    """
    params: dict = {"query": query, "from": from_time, "to": to_time, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/absolute", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_keyword(
    query: str,
    keyword: str = "last 1 hour",
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with a keyword time range.

    Args:
        query: Graylog search query (Lucene syntax)
        keyword: Natural language time range (e.g. "last 1 hour", "yesterday")
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = all)
        stream_id: Limit search to a specific stream ID (optional)
    """
    params: dict = {"query": query, "keyword": keyword, "limit": limit}
    if fields:
        params["fields"] = fields
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/keyword", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_message(message_id: str, index: str) -> dict:
    """Retrieve a specific message by ID.

    Args:
        message_id: The message ID
        index: The Elasticsearch index containing the message
    """
    try:
        return _get(f"/messages/{index}/{message_id}")
    except Exception as e:
        return _err(e)


# ── Aggregations ───────────────────────────────────────────────────────────


@mcp.tool()
def search_terms(
    field: str,
    query: str = "*",
    range_seconds: int = 3600,
    size: int = 10,
    stream_id: str = "",
) -> dict:
    """Get top-N values for a field (term frequency / cardinality).

    Useful for finding top source IPs, usernames, error codes, etc.

    Args:
        field: Field name to aggregate (e.g. "source", "gl2_source_input")
        query: Filter query in Lucene syntax (default: all messages)
        range_seconds: How far back to search in seconds (default: 3600 = 1 hour)
        size: Number of top values to return (default: 10)
        stream_id: Limit to a specific stream ID (optional)
    """
    params: dict = {"field": field, "query": query, "range": range_seconds, "size": size}
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/relative/terms", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_stats(
    field: str,
    query: str = "*",
    range_seconds: int = 3600,
    stream_id: str = "",
) -> dict:
    """Get statistical summary for a numeric field (min, max, mean, sum, stddev).

    Args:
        field: Numeric field name (e.g. "http_response_code", "took_ms")
        query: Filter query in Lucene syntax (default: all messages)
        range_seconds: How far back to search in seconds (default: 3600 = 1 hour)
        stream_id: Limit to a specific stream ID (optional)
    """
    params: dict = {"field": field, "query": query, "range": range_seconds}
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/relative/stats", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_histogram(
    query: str = "*",
    range_seconds: int = 3600,
    interval: str = "hour",
    stream_id: str = "",
) -> dict:
    """Get message count over time (time-bucketed histogram).

    Useful for spotting spikes or drops in log volume.

    Args:
        query: Filter query in Lucene syntax (default: all messages)
        range_seconds: How far back to search in seconds (default: 3600 = 1 hour)
        interval: Bucket size — minute, hour, day, week, month, quarter, year
        stream_id: Limit to a specific stream ID (optional)
    """
    params: dict = {"query": query, "range": range_seconds, "interval": interval}
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/relative/histogram", params)
    except Exception as e:
        return _err(e)


@mcp.tool()
def search_field_histogram(
    field: str,
    query: str = "*",
    range_seconds: int = 3600,
    interval: str = "hour",
    stream_id: str = "",
) -> dict:
    """Get a numeric field's value distribution over time.

    Args:
        field: Numeric field name (e.g. "took_ms", "bytes")
        query: Filter query in Lucene syntax (default: all messages)
        range_seconds: How far back to search in seconds (default: 3600 = 1 hour)
        interval: Bucket size — minute, hour, day, week, month, quarter, year
        stream_id: Limit to a specific stream ID (optional)
    """
    params: dict = {
        "field": field,
        "query": query,
        "range": range_seconds,
        "interval": interval,
    }
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    try:
        return _get("/search/universal/relative/fieldhistogram", params)
    except Exception as e:
        return _err(e)


# ── Streams ────────────────────────────────────────────────────────────────


@mcp.tool()
def list_streams() -> dict:
    """List all streams configured in Graylog."""
    try:
        return _get("/streams")
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_stream(stream_id: str) -> dict:
    """Get details for a specific stream.

    Args:
        stream_id: The stream ID
    """
    try:
        return _get(f"/streams/{stream_id}")
    except Exception as e:
        return _err(e)


@mcp.tool()
def find_stream(name: str) -> dict:
    """Find streams whose title matches a name (case-insensitive substring match).

    Call this at the start of an investigation to resolve a human-readable stream
    name (e.g. "firewall", "proxy", "edr", "windows") into its Graylog stream ID.
    Pass the returned id as stream_id to any search tool to scope queries to that
    stream only instead of searching across all streams.

    Args:
        name: Partial or full stream title to search for (e.g. "firewall", "proxy", "edr")
    """
    try:
        result = _get("/streams")
        streams = result.get("streams", [])
        name_lower = name.lower()
        matches = [
            {
                "id": s.get("id"),
                "title": s.get("title"),
                "description": s.get("description", ""),
                "disabled": s.get("disabled", False),
            }
            for s in streams
            if name_lower in s.get("title", "").lower()
        ]
        return {"query": name, "matches": matches, "total": len(matches)}
    except Exception as e:
        return _err(e)


# ── Alerts / Events ───────────────────────────────────────────────────────


@mcp.tool()
def search_events(
    query: str = "",
    timerange_from: int = 3600,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search alert events in Graylog.

    Args:
        query: Filter query (optional)
        timerange_from: How far back in seconds (default: 3600 = 1 hour)
        page: Page number (default: 1)
        per_page: Results per page (default: 50)
    """
    try:
        return _post(
            "/events/search",
            {
                "query": query,
                "timerange": {"type": "relative", "range": timerange_from},
                "page": page,
                "per_page": per_page,
            },
        )
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_event_definitions() -> dict:
    """List all event/alert definitions configured in Graylog."""
    try:
        return _get("/events/definitions")
    except Exception as e:
        return _err(e)


# ── Pipelines ──────────────────────────────────────────────────────────────


@mcp.tool()
def list_pipelines() -> dict:
    """List all processing pipelines configured in Graylog."""
    try:
        return _get("/system/pipelines/pipeline")
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_pipeline(pipeline_id: str) -> dict:
    """Get details for a specific processing pipeline, including its stages and rules.

    Args:
        pipeline_id: The pipeline ID
    """
    try:
        return _get(f"/system/pipelines/pipeline/{pipeline_id}")
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_pipeline_rules() -> dict:
    """List all pipeline rules configured in Graylog."""
    try:
        return _get("/system/pipelines/rule")
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_pipeline_rule(rule_id: str) -> dict:
    """Get a specific pipeline rule, including its source code.

    Args:
        rule_id: The pipeline rule ID
    """
    try:
        return _get(f"/system/pipelines/rule/{rule_id}")
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_pipeline_connections() -> dict:
    """List which streams are connected to which processing pipelines."""
    try:
        return _get("/system/pipelines/connections")
    except Exception as e:
        return _err(e)


# ── Dashboards & Saved Searches ────────────────────────────────────────────


@mcp.tool()
def list_dashboards() -> dict:
    """List all dashboards in Graylog."""
    try:
        return _get("/dashboards")
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_dashboard(dashboard_id: str) -> dict:
    """Get a specific dashboard with its widget list.

    Args:
        dashboard_id: The dashboard ID
    """
    try:
        return _get(f"/dashboards/{dashboard_id}")
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_saved_searches() -> dict:
    """List all saved searches.

    Tries the Graylog 5.x/6.x Views API first, falls back to the 4.x saved search API.
    """
    try:
        return _get("/search/views", {"type": "SEARCH"})
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            try:
                return _get("/search/saved")
            except Exception as e2:
                return _err(e2)
        return _err(e)
    except Exception as e:
        return _err(e)


@mcp.tool()
def get_saved_search(search_id: str) -> dict:
    """Get a specific saved search by ID.

    Tries the Graylog 5.x/6.x Views API first, falls back to the 4.x saved search API.

    Args:
        search_id: The saved search or view ID
    """
    try:
        return _get(f"/search/views/{search_id}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            try:
                return _get(f"/search/saved/{search_id}")
            except Exception as e2:
                return _err(e2)
        return _err(e)
    except Exception as e:
        return _err(e)


# ── Investigation ─────────────────────────────────────────────────────────


@mcp.tool()
def investigate(
    indicator: str,
    range_seconds: int = 86400,
    limit: int = 50,
    stream_id: str = "",
) -> dict:
    """Investigate any indicator across all Graylog data in one shot.

    Accepts any value — IP address, username, domain, file hash, process name,
    or any arbitrary string. Runs a coordinated set of queries internally and
    returns a consolidated report covering:
      - Recent matching messages
      - Activity timeline (auto-bucketed by time range)
      - Related alerts/events
      - Top co-occurring field values (source, app, level, facility, input)

    Args:
        indicator: The value to investigate (IP, username, domain, hash, string, etc.)
        range_seconds: How far back to search in seconds (default: 86400 = 24 hours)
        limit: Max messages in the recent hits section (default: 50)
        stream_id: Limit investigation to a specific stream (optional)
    """
    query = f'"{indicator}"'
    errors: list[str] = []

    filter_param = {"filter": f"streams:{stream_id}"} if stream_id else {}

    if range_seconds <= 3600:
        interval = "minute"
    elif range_seconds <= 86400:
        interval = "hour"
    elif range_seconds <= 604800:
        interval = "day"
    else:
        interval = "week"

    def _safe(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            errors.append(str(exc))
            return None

    messages = _safe(
        _get,
        "/search/universal/relative",
        {"query": query, "range": range_seconds, "limit": limit, **filter_param},
    )

    timeline = _safe(
        _get,
        "/search/universal/relative/histogram",
        {"query": query, "range": range_seconds, "interval": interval, **filter_param},
    )

    alerts = _safe(
        _post,
        "/events/search",
        {
            "query": indicator,
            "timerange": {"type": "relative", "range": range_seconds},
            "page": 1,
            "per_page": 20,
        },
    )

    soc_fields = ["source", "application_name", "level", "facility", "gl2_source_input"]
    top_co_occurring: dict = {}
    for field in soc_fields:
        try:
            result = _get(
                "/search/universal/relative/terms",
                {"field": field, "query": query, "range": range_seconds, "size": 5, **filter_param},
            )
            if result.get("terms"):
                top_co_occurring[field] = result["terms"]
        except Exception:
            pass

    total_messages = (
        messages.get("total_results") or messages.get("total", 0) if messages else 0
    )
    total_alerts = (
        alerts.get("total_events") or alerts.get("total", 0) if alerts else 0
    )

    report: dict = {
        "indicator": indicator,
        "range_seconds": range_seconds,
        "summary": {
            "total_messages": total_messages,
            "related_alerts": total_alerts,
        },
        "recent_messages": messages.get("messages", []) if messages else [],
        "activity_timeline": {
            "interval": interval,
            "results": timeline.get("results", {}) if timeline else {},
        },
        "related_alerts": alerts.get("events", []) if alerts else [],
        "top_co_occurring": top_co_occurring,
    }
    if errors:
        report["errors"] = errors
    return report


# ── System ─────────────────────────────────────────────────────────────────


@mcp.tool()
def system_overview() -> dict:
    """Get Graylog system overview (version, cluster, status)."""
    try:
        return _get("/system")
    except Exception as e:
        return _err(e)


@mcp.tool()
def list_inputs() -> dict:
    """List all configured inputs in Graylog."""
    try:
        return _get("/system/inputs")
    except Exception as e:
        return _err(e)


if __name__ == "__main__":
    mcp.run(transport="stdio")
