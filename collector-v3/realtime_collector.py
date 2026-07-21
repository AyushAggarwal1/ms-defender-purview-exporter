#!/usr/bin/env python3
"""Continuously stream Microsoft Defender XDR and Microsoft Purview activity to JSON Lines files.

This is a real-time companion to collector.py. Instead of exporting one fixed
[--start, --end) window to a single JSON file, it polls each source on an
interval, tracks a per-source checkpoint so every cycle only fetches data
newer than the last successful poll, and appends newly seen records to
per-stream .jsonl files under --output-dir. Checkpoints and the Advanced
Hunting table-schema cache persist to state.json so the process can be
stopped and restarted without creating gaps or duplicate re-fetches.

Reuses the authentication, HTTP retry, and collection logic in collector.py.

Data has its own backend ingestion delay at Microsoft (Advanced Hunting and
the Purview activity feed are not instantaneous), so --lag-seconds trails the
polling window behind wall-clock "now" to reduce the chance of querying past
the edge of data that has not landed yet.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from dotenv import load_dotenv

from collector import (
    DEFAULT_HUNTING_TABLES,
    DEFAULT_PURVIEW_CONTENT_TYPES,
    DEFENDER_SCOPE,
    GRAPH_SCOPE,
    HUNTING_MAX_ROWS_PER_QUERY,
    PURVIEW_SCOPE,
    AdvancedHuntingCollector,
    ApiClient,
    GraphSecurityCollector,
    PurviewActivityCollector,
    Settings,
    TokenProvider,
    build_correlated_email_index,
    iso_z,
    parse_datetime,
    unique_records,
    utc_now,
)

LOGGER = logging.getLogger("realtime_collector")

EMAIL_CORRELATION_TABLES = (
    "EmailEvents",
    "EmailAttachmentInfo",
    "EmailUrlInfo",
    "UrlClickEvents",
    "EmailPostDeliveryEvents",
)

_stop_requested = False


def _handle_shutdown_signal(signum: int, _frame: Any) -> None:
    global _stop_requested
    LOGGER.info("Received signal %s; finishing the current cycle and exiting.", signum)
    _stop_requested = True


class State:
    """Per-source checkpoints and the hunting-table schema cache, persisted as JSON."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.checkpoints: Dict[str, str] = {}
        self.hunting_has_timestamp: Dict[str, bool] = {}
        self.seen_purview_content_ids: Dict[str, List[str]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            LOGGER.warning("Could not read state file %s, starting fresh: %s", self.path, exc)
            return
        self.checkpoints = data.get("checkpoints", {})
        self.hunting_has_timestamp = data.get("hunting_has_timestamp", {})
        self.seen_purview_content_ids = data.get("seen_purview_content_ids", {})

    def save(self) -> None:
        payload = {
            "checkpoints": self.checkpoints,
            "hunting_has_timestamp": self.hunting_has_timestamp,
            # Cap remembered content IDs per content type so state.json cannot grow forever.
            "seen_purview_content_ids": {
                key: ids[-5000:] for key, ids in self.seen_purview_content_ids.items()
            },
        }
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(self.path)

    def get_checkpoint(self, key: str, default: datetime) -> datetime:
        raw = self.checkpoints.get(key)
        return parse_datetime(raw) if raw else default

    def set_checkpoint(self, key: str, value: datetime) -> None:
        self.checkpoints[key] = iso_z(value, timespec="microseconds")

    def remember_purview_ids(self, content_type: str, ids: Sequence[str]) -> None:
        if not ids:
            return
        existing = set(self.seen_purview_content_ids.get(content_type, []))
        existing.update(ids)
        self.seen_purview_content_ids[content_type] = list(existing)


class JsonlSink:
    """Append-only JSON Lines writer, one file per logical event stream."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, stream: str, records: Sequence[Dict[str, Any]]) -> None:
        if not records:
            return
        path = self.output_dir / f"{stream}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, default=str))
                handle.write("\n")


def tag(records: Sequence[Dict[str, Any]], meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{**record, "_meta": meta} for record in records]


def poll_graph_security(
    collector: GraphSecurityCollector,
    state: State,
    sink: JsonlSink,
    window_end: datetime,
    lookback: timedelta,
    tenant_id: str,
) -> None:
    key = "graph_security"
    start = state.get_checkpoint(key, window_end - lookback)
    if start >= window_end:
        return

    LOGGER.info("Polling Graph Security incidents/alerts %s -> %s", iso_z(start), iso_z(window_end))
    data = collector.collect(start, window_end)
    collected_at = iso_z(utc_now())
    base_meta = {
        "source": "graph_security",
        "tenantId": tenant_id,
        "windowStart": iso_z(start),
        "windowEnd": iso_z(window_end),
        "collectedAt": collected_at,
    }
    sink.write("graph_incidents", tag(data["incidents"], {**base_meta, "stream": "incidents"}))
    sink.write("graph_alerts", tag(data["alerts"], {**base_meta, "stream": "alerts"}))
    if data["incidents"] or data["alerts"]:
        LOGGER.info("Graph Security: %d incidents, %d alerts", len(data["incidents"]), len(data["alerts"]))
    state.set_checkpoint(key, window_end)


def poll_hunting_table(
    collector: AdvancedHuntingCollector,
    table: str,
    state: State,
    window_end: datetime,
    lookback: timedelta,
    sink: JsonlSink,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    key = f"hunting:{table}"
    start = state.get_checkpoint(key, window_end - lookback)
    if start >= window_end:
        return []

    has_timestamp = state.hunting_has_timestamp.get(table)
    if has_timestamp is None:
        try:
            _, has_timestamp = collector._inspect_table(table)
        except Exception:
            LOGGER.exception("Schema probe failed for hunting table %s", table)
            return []
        state.hunting_has_timestamp[table] = has_timestamp

    collected_at = iso_z(utc_now())

    if not has_timestamp:
        # Snapshot/entity tables have no Timestamp column; re-fetch the current
        # snapshot each cycle rather than tracking an incremental window.
        try:
            response = collector.run_query(f"{table}\n| take {HUNTING_MAX_ROWS_PER_QUERY}")
        except Exception:
            LOGGER.exception("Snapshot query failed for hunting table %s", table)
            return []
        rows = [row for row in response.get("Results", []) if isinstance(row, dict)]
        meta = {
            "source": "advanced_hunting",
            "table": table,
            "collectionMode": "snapshot",
            "tenantId": tenant_id,
            "collectedAt": collected_at,
        }
        sink.write(f"hunting_{table}", tag(rows, meta))
        state.set_checkpoint(key, window_end)
        return rows

    try:
        rows, _schema, _stats, _slices, truncated = collector._collect_timestamp_slice(table, start, window_end)
    except Exception:
        LOGGER.exception("Hunting query failed for table %s", table)
        return []

    if truncated:
        LOGGER.warning(
            "Hunting table %s hit the 100k row limit even at the minimum slice for %s -> %s; some rows were dropped",
            table,
            iso_z(start),
            iso_z(window_end),
        )

    meta = {
        "source": "advanced_hunting",
        "table": table,
        "collectionMode": "time_sliced",
        "windowStart": iso_z(start),
        "windowEnd": iso_z(window_end),
        "tenantId": tenant_id,
        "collectedAt": collected_at,
    }
    sink.write(f"hunting_{table}", tag(rows, meta))
    if rows:
        LOGGER.info("Hunting table %s: %d new row(s)", table, len(rows))
    state.set_checkpoint(key, window_end)
    return rows


def poll_purview_content_type(
    collector: PurviewActivityCollector,
    content_type: str,
    state: State,
    window_end: datetime,
    lookback: timedelta,
    sink: JsonlSink,
    tenant_id: str,
) -> None:
    key = f"purview:{content_type}"
    earliest_listable = window_end - timedelta(days=7)
    start = state.get_checkpoint(key, window_end - lookback)
    if start < earliest_listable:
        LOGGER.warning(
            "Purview checkpoint for %s is older than the 7-day listing window; advancing to %s",
            content_type,
            iso_z(earliest_listable),
        )
        start = earliest_listable
    if start >= window_end:
        return

    # The Management Activity API requires listing windows of 24 hours or less.
    end = min(window_end, start + timedelta(hours=24))

    try:
        blobs = collector.list_content(content_type, start, end)
    except Exception:
        LOGGER.exception("Purview content listing failed for %s", content_type)
        return

    seen = set(state.seen_purview_content_ids.get(content_type, []))
    new_blobs: Dict[str, Dict[str, Any]] = {}
    for blob in blobs:
        content_id = str(blob.get("contentId") or blob.get("contentUri") or "")
        if content_id and content_id not in seen:
            new_blobs[content_id] = blob

    events: List[Dict[str, Any]] = []
    downloaded_ids: List[str] = []
    for content_id, blob in new_blobs.items():
        content_uri = blob.get("contentUri")
        if not content_uri:
            continue
        try:
            events.extend(collector.retrieve_blob(str(content_uri)))
            downloaded_ids.append(content_id)
        except Exception:
            LOGGER.exception("Purview content download failed for %s (%s)", content_type, content_uri)

    deduplicated = unique_records(events)
    if deduplicated:
        meta = {
            "source": "purview_activity_feed",
            "contentType": content_type,
            "tenantId": tenant_id,
            "collectedAt": iso_z(utc_now()),
        }
        sink.write(f"purview_{content_type}", tag(deduplicated, meta))
        LOGGER.info("Purview %s: %d new event(s)", content_type, len(deduplicated))

    state.remember_purview_ids(content_type, downloaded_ids)
    state.set_checkpoint(key, end)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Continuously poll Microsoft Defender XDR and Microsoft Purview and stream new activity to JSON Lines files."
    )
    parser.add_argument("--output-dir", default="realtime-export", help="Directory for .jsonl streams and state.json.")
    parser.add_argument("--state-file", help="Checkpoint/state file path. Defaults to <output-dir>/state.json.")
    parser.add_argument("--poll-interval", type=float, default=300, help="Seconds between poll cycles. Default: 300.")
    parser.add_argument(
        "--lag-seconds",
        type=float,
        default=180,
        help="Trail the polling window this many seconds behind now, to absorb backend ingestion delay. Default: 180.",
    )
    parser.add_argument(
        "--initial-lookback-minutes",
        type=float,
        default=60,
        help="How far back the first poll cycle reaches for a source with no checkpoint yet. Default: 60.",
    )
    parser.add_argument(
        "--hunting-table",
        action="append",
        dest="hunting_tables",
        help="Advanced Hunting table to poll. Repeatable. Defaults to all documented tables.",
    )
    parser.add_argument(
        "--purview-content-type",
        action="append",
        dest="purview_content_types",
        help="Purview activity content type to poll. Repeatable.",
    )
    parser.add_argument("--skip-graph-security", action="store_true", help="Skip Graph incidents/alerts.")
    parser.add_argument("--skip-hunting", action="store_true", help="Skip Defender Advanced Hunting.")
    parser.add_argument("--skip-purview", action="store_true", help="Skip the Purview activity feed.")
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit, instead of looping forever.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def run_cycle(
    args: argparse.Namespace,
    settings: Settings,
    state: State,
    sink: JsonlSink,
    graph_collector: GraphSecurityCollector,
    hunting_collector: AdvancedHuntingCollector,
    purview_collector: PurviewActivityCollector,
    hunting_tables: Sequence[str],
    purview_content_types: Sequence[str],
    enabled_purview_types: Optional[set],
    lookback: timedelta,
    lag: timedelta,
) -> Optional[set]:
    window_end = utc_now() - lag

    if not args.skip_graph_security:
        try:
            poll_graph_security(graph_collector, state, sink, window_end, lookback, settings.tenant_id)
        except Exception:
            LOGGER.exception("Graph Security poll cycle failed")

    if not args.skip_hunting:
        cycle_email_rows: Dict[str, List[Dict[str, Any]]] = {}
        for table in hunting_tables:
            try:
                rows = poll_hunting_table(hunting_collector, table, state, window_end, lookback, sink, settings.tenant_id)
            except Exception:
                LOGGER.exception("Hunting poll cycle failed for table %s", table)
                continue
            if table in EMAIL_CORRELATION_TABLES and rows:
                cycle_email_rows[table] = rows

        if cycle_email_rows:
            correlated = build_correlated_email_index({t: {"results": r} for t, r in cycle_email_rows.items()})
            if correlated:
                meta = {
                    "source": "advanced_hunting",
                    "stream": "correlated_emails",
                    "tenantId": settings.tenant_id,
                    "collectedAt": iso_z(utc_now()),
                    "note": "Correlated from tables collected in this cycle only; an email's parts split across "
                            "cycles are not merged in a single record.",
                }
                sink.write("correlated_emails", tag(correlated, meta))

    if not args.skip_purview:
        if enabled_purview_types is None:
            try:
                enabled_purview_types = {
                    str(item.get("contentType"))
                    for item in purview_collector.list_subscriptions()
                    if str(item.get("status", "")).lower() == "enabled"
                }
            except Exception:
                LOGGER.exception("Could not list Purview subscriptions")
                enabled_purview_types = set()

        for content_type in purview_content_types:
            if content_type not in enabled_purview_types:
                LOGGER.warning(
                    "Purview subscription %s is not enabled; run: python collector.py --start-subscription %s",
                    content_type,
                    content_type,
                )
                continue
            try:
                poll_purview_content_type(
                    purview_collector, content_type, state, window_end, lookback, sink, settings.tenant_id
                )
            except Exception:
                LOGGER.exception("Purview poll cycle failed for %s", content_type)

    return enabled_purview_types


def main() -> int:
    load_dotenv()
    args = build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        settings = Settings.from_environment()
    except Exception as exc:
        LOGGER.error("Configuration error: %s", exc)
        return 2

    output_dir = Path(args.output_dir).expanduser().resolve()
    state_path = Path(args.state_file).expanduser().resolve() if args.state_file else output_dir / "state.json"
    state = State(state_path)
    sink = JsonlSink(output_dir)

    token_provider = TokenProvider(settings)
    graph_collector = GraphSecurityCollector(ApiClient(token_provider, GRAPH_SCOPE))
    hunting_collector = AdvancedHuntingCollector(ApiClient(token_provider, DEFENDER_SCOPE, timeout_seconds=210), chunk_hours=1)
    purview_collector = PurviewActivityCollector(ApiClient(token_provider, PURVIEW_SCOPE), settings)

    hunting_tables = tuple(args.hunting_tables or DEFAULT_HUNTING_TABLES)
    purview_content_types = tuple(args.purview_content_types or DEFAULT_PURVIEW_CONTENT_TYPES)
    lookback = timedelta(minutes=args.initial_lookback_minutes)
    lag = timedelta(seconds=args.lag_seconds)

    signal.signal(signal.SIGINT, _handle_shutdown_signal)
    signal.signal(signal.SIGTERM, _handle_shutdown_signal)

    LOGGER.info("Streaming to %s (state: %s)", output_dir, state_path)

    enabled_purview_types: Optional[set] = None

    while True:
        cycle_started = time.monotonic()

        enabled_purview_types = run_cycle(
            args,
            settings,
            state,
            sink,
            graph_collector,
            hunting_collector,
            purview_collector,
            hunting_tables,
            purview_content_types,
            enabled_purview_types,
            lookback,
            lag,
        )

        state.save()

        if args.once or _stop_requested:
            break

        elapsed = time.monotonic() - cycle_started
        sleep_for = max(0.0, args.poll_interval - elapsed)
        LOGGER.debug("Cycle finished in %.1fs; sleeping %.1fs", elapsed, sleep_for)
        remaining = sleep_for
        while remaining > 0 and not _stop_requested:
            step = min(1.0, remaining)
            time.sleep(step)
            remaining -= step

    LOGGER.info("Shutdown complete; state saved to %s", state_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
