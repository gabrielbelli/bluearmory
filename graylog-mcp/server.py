"""Graylog MCP Server.

Wraps the Graylog REST API and exposes search, streams, alerts, aggregations,
pipelines, and dashboards as MCP tools for SOC workflows.
"""

import logging
import os
import uuid
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

load_dotenv(Path(__file__).parent.parent / ".env")
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
def _post(path: str, body: dict, params: dict | None = None) -> dict:
    logger.debug("POST %s", path)
    r = _client().post(path, json=body, params=params)
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


def _build_timerange(range_seconds: int | None, from_time: str, to_time: str) -> dict:
    if from_time and to_time:
        return {"type": "absolute", "from": from_time, "to": to_time}
    return {"type": "relative", "range": range_seconds or 86400}


def _build_filter(stream_ids: list[str]) -> dict | None:
    filters = [{"type": "stream", "id": sid} for sid in stream_ids if sid]
    if not filters:
        return None
    return {"type": "or", "filters": filters}


def _sync_search(body: dict, timeout_ms: int) -> dict:
    return _post("/views/search/sync", body, params={"timeout": timeout_ms})


# ── Search (legacy — Graylog 4.x / 5.x) ──────────────────────────────────


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


# ── Search & Aggregation (Graylog 6.x — views/search/sync) ────────────────


@mcp.tool()
def search_messages(
    query: str,
    streams: list[str] | None = None,
    stream_categories: list[str] | None = None,
    fields: list[str] | None = None,
    limit: int = 50,
    offset: int = 0,
    range_seconds: int = 86400,
    from_time: str = "",
    to_time: str = "",
    sort_field: str = "timestamp",
    sort_order: str = "DESC",
    timeout_ms: int = 15000,
) -> dict:
    """Search Graylog 6.x messages.

    Use this instead of search_relative or search_absolute on Graylog 6.x.
    The legacy /search/universal/* endpoints return no results on Graylog 6.x.

    Pass the timerange via range_seconds or from_time+to_time — never embed time
    in the query string. List only the fields you need; without fields, only
    source and timestamp are returned. Scope to specific streams for performance.

    Args:
        query: Lucene query string (e.g. 'srcip:"1.2.3.4"', 'alert_severity:1')
        streams: Stream IDs to scope the search (empty = all streams)
        stream_categories: Illuminate stream categories — Graylog 6.x with Illuminate only
        fields: Field names to return. Empty = source and timestamp only.
        limit: Maximum messages to return (default 50)
        offset: Pagination offset (default 0)
        range_seconds: Relative lookback in seconds (default 86400 = 24h).
                       Ignored when from_time and to_time are both provided.
        from_time: Absolute start time ISO 8601 (e.g. 2025-04-01T00:00:00.000Z).
        to_time: Absolute end time ISO 8601.
        sort_field: Field to sort by (default: timestamp)
        sort_order: ASC or DESC (default: DESC)
        timeout_ms: Server-side query timeout in milliseconds (default 15000)
    """
    try:
        search_type: dict = {
            "id": "msgs",
            "type": "messages",
            "limit": limit,
            "offset": offset,
            "sort": [{"field": sort_field, "order": sort_order}],
        }
        if fields:
            search_type["fields"] = fields

        query_obj: dict = {
            "id": str(uuid.uuid4()),
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": _build_timerange(range_seconds, from_time, to_time),
            "search_types": [search_type],
        }
        flt = _build_filter(streams or [])
        if flt:
            query_obj["filter"] = flt

        raw = _sync_search({"queries": [query_obj]}, timeout_ms)
        qid = query_obj["id"]
        st = raw.get("results", {}).get(qid, {}).get("search_types", {}).get("msgs", {})
        messages = [m.get("message", m) for m in st.get("messages", [])]
        return {
            "total": st.get("total_results", 0),
            "messages": messages,
            "query": query,
        }
    except Exception as e:
        return _err(e)


@mcp.tool()
def aggregate_messages(
    groupings: list[dict],
    metrics: list[dict] | None = None,
    query: str = "*",
    streams: list[str] | None = None,
    stream_categories: list[str] | None = None,
    range_seconds: int = 3600,
    from_time: str = "",
    to_time: str = "",
    timeout_ms: int = 15000,
) -> dict:
    """Aggregate and group Graylog 6.x messages by field values or time buckets.

    Use this instead of search_terms or search_histogram on Graylog 6.x.

    Each grouping is either a field-value bucket or a time bucket:
      {"field": "source", "limit": 10}               — top-N values for a field
      {"field": "timestamp", "granularity": "hour"}   — time histogram

    granularity options: "auto", "minute", "hour", "day", "week", "month"

    Each metric defines what to compute per bucket:
      {"function": "count"}                    — message count (default)
      {"function": "avg", "field": "bytes"}    — numeric field metric

    metric functions: count, avg, min, max, sum, stddev, card, latest

    Examples:
      Top 10 sources:  groupings=[{"field":"source","limit":10}], metrics=[{"function":"count"}]
      Hourly volume:   groupings=[{"field":"timestamp","granularity":"hour"}], metrics=[{"function":"count"}]
      Avg bytes/dest:  groupings=[{"field":"dstip","limit":20}], metrics=[{"function":"avg","field":"bytes"}]

    Args:
        groupings: Required. One or more grouping dicts.
        metrics: Metric dicts. Defaults to [{"function": "count"}].
        query: Lucene filter query (default: all messages)
        streams: Stream IDs to scope the search (empty = all streams)
        stream_categories: Illuminate stream categories — Graylog 6.x with Illuminate only
        range_seconds: Relative time window in seconds (default 3600 = 1 hour)
        from_time: Absolute start time ISO 8601. Pair with to_time for absolute range.
        to_time: Absolute end time ISO 8601.
        timeout_ms: Server-side timeout in milliseconds (default 15000)
    """
    _UNIT_MAP = {
        "minute": "MINUTES", "minutes": "MINUTES",
        "hour": "HOURS", "hours": "HOURS",
        "day": "DAYS", "days": "DAYS",
        "week": "WEEKS", "weeks": "WEEKS",
        "month": "MONTHS", "months": "MONTHS",
    }
    try:
        row_groups = []
        for g in groupings:
            field = g.get("field", "")
            if field == "timestamp" or "granularity" in g:
                gran = g.get("granularity", "auto")
                if gran == "auto":
                    row_groups.append({
                        "type": "time",
                        "field": "timestamp",
                        "interval": {"type": "auto", "scaling": 1.0},
                    })
                else:
                    unit = _UNIT_MAP.get(gran.lower(), "HOURS")
                    row_groups.append({
                        "type": "time",
                        "field": "timestamp",
                        "interval": {"type": "timeunit", "value": 1, "unit": unit},
                    })
            else:
                row_groups.append({
                    "type": "values",
                    "field": field,
                    "limit": g.get("limit", 10),
                })

        series = []
        for i, m in enumerate(metrics or [{"function": "count"}]):
            fn = m["function"].lower()
            s: dict = {"type": fn, "id": f"{fn}_{i}"}
            if "field" in m:
                s["field"] = m["field"]
            series.append(s)

        search_type = {
            "id": "agg_0",
            "type": "pivot",
            "row_groups": row_groups,
            "column_groups": [],
            "series": series,
            "rollup": False,
        }
        query_obj: dict = {
            "id": str(uuid.uuid4()),
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": _build_timerange(range_seconds, from_time, to_time),
            "search_types": [search_type],
        }
        flt = _build_filter(streams or [])
        if flt:
            query_obj["filter"] = flt

        raw = _sync_search({"queries": [query_obj]}, timeout_ms)
        qid = query_obj["id"]
        st = raw.get("results", {}).get(qid, {}).get("search_types", {}).get("agg_0", {})
        rows = [
            {
                "key": row.get("key", []),
                "values": {
                    v.get("id", f"v{i}"): v.get("value")
                    for i, v in enumerate(row.get("values", []))
                },
            }
            for row in st.get("rows", [])
            if row.get("key")
        ]
        return {"groupings": [g.get("field") for g in groupings], "rows": rows}
    except Exception as e:
        return _err(e)


# ── Aggregations (legacy — Graylog 4.x / 5.x) ────────────────────────────


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


# ── System ─────────────────────────────────────────────────────────────────


@mcp.tool()
def get_system_status() -> dict:
    """Get Graylog system information (version, cluster ID, hostname, timezone, status)."""
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
