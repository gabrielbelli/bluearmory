"""Graylog MCP Server.

Wraps the Graylog REST API and exposes search, streams, alerts, aggregations,
pipelines, and dashboards as MCP tools for SOC workflows.
"""

import json
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


def _parse_stream_ids(stream_ids: str) -> list[str]:
    return [s.strip() for s in stream_ids.split(",") if s.strip()]


def _sync_search(body: dict, timeout_ms: int) -> dict:
    return _post("/views/search/sync", body, params={"timeout": timeout_ms})


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


# ── Graylog 6.x Search (views/search/sync) ────────────────────────────────


@mcp.tool()
def search_sync(
    query: str,
    range_seconds: int = 86400,
    from_time: str = "",
    to_time: str = "",
    limit: int = 50,
    fields: str = "",
    stream_ids: str = "",
    sort_field: str = "timestamp",
    sort_order: str = "DESC",
    timeout_ms: int = 15000,
) -> dict:
    """Search Graylog 6.x messages using the views/search/sync API.

    Use this instead of search_relative or search_absolute on Graylog 6.x.
    The legacy /search/universal/* endpoints return no results on Graylog 6.x.

    Args:
        query: Lucene query string (e.g. 'srcip:"1.2.3.4"', 'alert_severity:1')
        range_seconds: Relative time window in seconds (default 86400 = 24h).
                       Ignored when from_time and to_time are both set.
        from_time: Absolute start time ISO 8601 (e.g. 2025-04-01T00:00:00.000Z).
                   Provide together with to_time to use an absolute range.
        to_time: Absolute end time ISO 8601.
        limit: Maximum number of messages to return (default 50)
        fields: Comma-separated field names to include in each message.
                Empty string returns all stored fields.
        stream_ids: Comma-separated stream IDs to scope the search.
                    Empty string searches across all streams.
        sort_field: Field to sort by (default: timestamp)
        sort_order: ASC or DESC (default: DESC)
        timeout_ms: Server-side query timeout in milliseconds (default 15000)
    """
    try:
        sid_list = _parse_stream_ids(stream_ids)
        fields_list = [f.strip() for f in fields.split(",") if f.strip()]
        search_type: dict = {
            "id": "msgs",
            "type": "messages",
            "limit": limit,
            "offset": 0,
            "sort": [{"field": sort_field, "order": sort_order}],
        }
        if fields_list:
            search_type["fields"] = fields_list

        query_obj: dict = {
            "id": str(uuid.uuid4()),
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": _build_timerange(range_seconds, from_time, to_time),
            "search_types": [search_type],
        }
        f = _build_filter(sid_list)
        if f:
            query_obj["filter"] = f

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
def aggregate_terms(
    field: str,
    query: str = "*",
    range_seconds: int = 86400,
    from_time: str = "",
    to_time: str = "",
    size: int = 20,
    stream_ids: str = "",
    timeout_ms: int = 15000,
) -> dict:
    """Get top-N values for a field using the Graylog 6.x views/search/sync API.

    Use this instead of search_terms on Graylog 6.x.

    Args:
        field: Field name to aggregate (e.g. "dstip", "alert_signature", "srcuser")
        query: Lucene filter query (default: all messages)
        range_seconds: Relative time window in seconds (default 86400 = 24h)
        from_time: Absolute start time ISO 8601. Pair with to_time for absolute range.
        to_time: Absolute end time ISO 8601.
        size: Number of top values to return (default 20)
        stream_ids: Comma-separated stream IDs. Empty = all streams.
        timeout_ms: Server-side timeout in milliseconds (default 15000)
    """
    try:
        sid_list = _parse_stream_ids(stream_ids)
        search_type = {
            "id": "terms_0",
            "type": "pivot",
            "row_groups": [{"type": "values", "field": field, "limit": size}],
            "column_groups": [],
            "series": [{"type": "count", "id": "count", "field": None}],
            "rollup": False,
        }
        query_obj: dict = {
            "id": str(uuid.uuid4()),
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": _build_timerange(range_seconds, from_time, to_time),
            "search_types": [search_type],
        }
        f = _build_filter(sid_list)
        if f:
            query_obj["filter"] = f

        raw = _sync_search({"queries": [query_obj]}, timeout_ms)
        qid = query_obj["id"]
        st = raw.get("results", {}).get(qid, {}).get("search_types", {}).get("terms_0", {})
        terms = [
            {"value": row["key"][0], "count": row["values"][0].get("value", 0)}
            for row in st.get("rows", [])
            if row.get("key")
        ]
        return {"field": field, "terms": terms}
    except Exception as e:
        return _err(e)


@mcp.tool()
def aggregate_histogram(
    query: str = "*",
    range_seconds: int = 86400,
    from_time: str = "",
    to_time: str = "",
    interval: str = "auto",
    stream_ids: str = "",
    timeout_ms: int = 15000,
) -> dict:
    """Get message count bucketed over time using the Graylog 6.x views/search/sync API.

    Use this instead of search_histogram on Graylog 6.x.

    Args:
        query: Lucene filter query (default: all messages)
        range_seconds: Relative time window in seconds (default 86400 = 24h)
        from_time: Absolute start time ISO 8601. Pair with to_time for absolute range.
        to_time: Absolute end time ISO 8601.
        interval: Bucket size — "auto", "minute", "hour", "day", "week", "month".
                  "auto" lets Graylog choose based on the time range.
        stream_ids: Comma-separated stream IDs. Empty = all streams.
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
        sid_list = _parse_stream_ids(stream_ids)
        if interval == "auto":
            row_group = {
                "type": "time",
                "field": "timestamp",
                "interval": {"type": "auto", "scaling": 1.0},
            }
        else:
            unit = _UNIT_MAP.get(interval.lower(), "HOURS")
            row_group = {
                "type": "time",
                "field": "timestamp",
                "interval": {"type": "timeunit", "value": 1, "unit": unit},
            }
        search_type = {
            "id": "hist_0",
            "type": "pivot",
            "row_groups": [row_group],
            "column_groups": [],
            "series": [{"type": "count", "id": "count", "field": None}],
            "rollup": False,
        }
        query_obj: dict = {
            "id": str(uuid.uuid4()),
            "query": {"type": "elasticsearch", "query_string": query},
            "timerange": _build_timerange(range_seconds, from_time, to_time),
            "search_types": [search_type],
        }
        f = _build_filter(sid_list)
        if f:
            query_obj["filter"] = f

        raw = _sync_search({"queries": [query_obj]}, timeout_ms)
        qid = query_obj["id"]
        st = raw.get("results", {}).get(qid, {}).get("search_types", {}).get("hist_0", {})
        buckets = [
            {"timestamp": row["key"][0], "count": row["values"][0].get("value", 0)}
            for row in st.get("rows", [])
            if row.get("key")
        ]
        return {"interval": interval, "buckets": buckets}
    except Exception as e:
        return _err(e)


# ── Aggregations (legacy — Graylog 4.x/5.x only) ──────────────────────────


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


# ── Hunt (autonomous sub-agent) ────────────────────────────────────────────

try:
    import anthropic as _anthropic
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
HUNT_MODEL = os.environ.get("HUNT_MODEL", "claude-opus-4-7")


def _strip_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    try:
        end = text.index("---", 3)
        return text[end + 3:].lstrip("\n")
    except ValueError:
        return text


def _load_skill(name: str) -> str:
    # HUNT_SKILL_PATH overrides everything — useful in Docker where skills are mounted
    env_path = os.environ.get("HUNT_SKILL_PATH", "")
    candidates = (
        [Path(env_path)]
        if env_path
        else [
            Path(__file__).parent.parent / "skills" / name / "SKILL.md",
            Path(__file__).parent / "skills" / name / "SKILL.md",
            Path.home() / ".claude" / "skills" / name / "SKILL.md",
        ]
    )
    for p in candidates:
        if p.exists():
            return _strip_frontmatter(p.read_text())
    raise FileNotFoundError(
        f"Skill '{name}' not found. Looked in: {[str(p) for p in candidates]}"
    )


def _range_label(seconds: int) -> str:
    if seconds % 604800 == 0:
        n = seconds // 604800
        return f"last {n} week{'s' if n != 1 else ''}"
    if seconds % 86400 == 0:
        n = seconds // 86400
        return f"last {n} day{'s' if n != 1 else ''}"
    if seconds % 3600 == 0:
        n = seconds // 3600
        return f"last {n} hour{'s' if n != 1 else ''}"
    return f"last {seconds} seconds"


_HUNT_TOOL_SCHEMAS: list[dict] = [
    {
        "name": "list_streams",
        "description": "List all streams configured in Graylog.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "find_stream",
        "description": "Find streams whose title matches a name (case-insensitive substring match).",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Partial or full stream title to search for"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "search_sync",
        "description": (
            "Search Graylog 6.x messages using views/search/sync. "
            "Use instead of search_relative/search_absolute on Graylog 6.x."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Lucene query string"},
                "range_seconds": {"type": "integer", "description": "Relative lookback window in seconds (default 86400)"},
                "from_time": {"type": "string", "description": "Absolute start time ISO 8601"},
                "to_time": {"type": "string", "description": "Absolute end time ISO 8601"},
                "limit": {"type": "integer", "description": "Max messages to return (default 50)"},
                "fields": {"type": "string", "description": "Comma-separated field names"},
                "stream_ids": {"type": "string", "description": "Comma-separated stream IDs"},
                "sort_field": {"type": "string", "description": "Sort field (default: timestamp)"},
                "sort_order": {"type": "string", "description": "ASC or DESC (default: DESC)"},
                "timeout_ms": {"type": "integer", "description": "Server-side timeout ms (default 15000)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "aggregate_terms",
        "description": "Top-N field value counts using Graylog 6.x views/search/sync pivot.",
        "input_schema": {
            "type": "object",
            "properties": {
                "field": {"type": "string", "description": "Field name to aggregate"},
                "query": {"type": "string", "description": "Lucene filter query (default: *)"},
                "range_seconds": {"type": "integer", "description": "Relative lookback window in seconds"},
                "from_time": {"type": "string", "description": "Absolute start time ISO 8601"},
                "to_time": {"type": "string", "description": "Absolute end time ISO 8601"},
                "size": {"type": "integer", "description": "Number of top values (default 20)"},
                "stream_ids": {"type": "string", "description": "Comma-separated stream IDs"},
                "timeout_ms": {"type": "integer", "description": "Server-side timeout ms (default 15000)"},
            },
            "required": ["field"],
        },
    },
    {
        "name": "aggregate_histogram",
        "description": "Message count over time using Graylog 6.x views/search/sync pivot.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Lucene filter query (default: *)"},
                "range_seconds": {"type": "integer", "description": "Relative lookback window in seconds"},
                "from_time": {"type": "string", "description": "Absolute start time ISO 8601"},
                "to_time": {"type": "string", "description": "Absolute end time ISO 8601"},
                "interval": {"type": "string", "description": "Bucket size: auto, minute, hour, day, week, month"},
                "stream_ids": {"type": "string", "description": "Comma-separated stream IDs"},
                "timeout_ms": {"type": "integer", "description": "Server-side timeout ms (default 15000)"},
            },
            "required": [],
        },
    },
    {
        "name": "search_events",
        "description": "Search Graylog alert events with pagination.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Filter query (optional)"},
                "timerange_from": {"type": "integer", "description": "Lookback seconds (default 3600)"},
                "page": {"type": "integer", "description": "Page number (default 1)"},
                "per_page": {"type": "integer", "description": "Results per page (default 50)"},
            },
            "required": [],
        },
    },
    {
        "name": "list_event_definitions",
        "description": "List all event/alert definitions configured in Graylog.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]


def _dispatch_hunt_tool(name: str, kwargs: dict) -> dict:
    _dispatch: dict = {
        "list_streams": lambda k: list_streams(),
        "find_stream": lambda k: find_stream(**k),
        "search_sync": lambda k: search_sync(**k),
        "aggregate_terms": lambda k: aggregate_terms(**k),
        "aggregate_histogram": lambda k: aggregate_histogram(**k),
        "search_events": lambda k: search_events(**k),
        "list_event_definitions": lambda k: list_event_definitions(),
    }
    fn = _dispatch.get(name)
    if fn is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return fn(kwargs)
    except Exception as e:
        return _err(e)


@mcp.tool()
def hunt(
    indicator: str,
    range_seconds: int = 86400,
    model: str = "",
) -> str:
    """Run a full autonomous threat hunt for any indicator against Graylog.

    Loads the graylog-hunt skill as a system prompt and spins up a Claude
    sub-agent with access to all Graylog search tools. The agent follows the
    skill's multi-phase investigation workflow (stream discovery, parallel
    queries, SOC heuristics, auto-pivot) and returns a structured risk-tiered
    report with MITRE ATT&CK mapping.

    Requires ANTHROPIC_API_KEY to be set in the environment.

    Args:
        indicator: IP, CIDR, username, domain, file hash, process name, or free
                   text. May include a time suffix: "1.2.3.4 last 7 days".
        range_seconds: Default lookback window in seconds (default: 86400 = 24h).
                       Overridden if the indicator includes a "last N unit" suffix.
        model: Override the Claude model. Defaults to HUNT_MODEL env var
               (default: claude-opus-4-7).
    """
    if not _HAS_ANTHROPIC:
        return (
            "Error: 'anthropic' package not installed. "
            "Add anthropic>=0.50.0 to requirements.txt and rebuild the container."
        )
    if not ANTHROPIC_API_KEY:
        return "Error: ANTHROPIC_API_KEY environment variable is not set."

    try:
        skill_text = _load_skill("graylog-hunt")
    except FileNotFoundError as e:
        return f"Error loading skill: {e}"

    effective_model = model or HUNT_MODEL
    client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY, timeout=300)

    user_message = f"Hunt for: {indicator} {_range_label(range_seconds)}"
    system: list[dict] = [
        {
            "type": "text",
            "text": skill_text,
            "cache_control": {"type": "ephemeral"},
        }
    ]
    messages: list[dict] = [{"role": "user", "content": user_message}]

    for _ in range(60):
        response = client.messages.create(
            model=effective_model,
            max_tokens=16384,
            system=system,
            tools=_HUNT_TOOL_SCHEMAS,
            messages=messages,
            thinking={"type": "adaptive"},
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    return block.text
            return "(Hunt completed but produced no text output)"

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = _dispatch_hunt_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str),
                    })
            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            continue

        break

    return "Error: Hunt exceeded maximum iterations (60) without completing."


if __name__ == "__main__":
    mcp.run(transport="stdio")
