#!/usr/bin/env python3
"""Export Microsoft Defender XDR and Microsoft Purview data to JSON.

Collected sources:
1. Microsoft Graph Security API
   - /security/incidents
   - /security/alerts_v2
2. Microsoft Defender XDR Advanced Hunting
   - Every table currently listed in the Microsoft Defender XDR hunting schema
   - Microsoft Graph runHuntingQuery when ThreatHunting.Read.All is available
   - Automatic fallback to the legacy Defender endpoint while it remains available
3. Microsoft Purview Audit Search API
   - /security/auditLog/queries and all returned audit record types
4. Office 365 Management Activity API
   - All five supported content types: Entra, Exchange, SharePoint, General, and DLP

The exporter preserves raw API fields. It also builds a correlated email index keyed
by NetworkMessageId when the relevant email tables are available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

import msal
import requests
from dotenv import load_dotenv

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEFENDER_SCOPE = "https://api.security.microsoft.com/.default"
PURVIEW_SCOPE = "https://manage.office.com/.default"

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_HUNTING_URL = f"{GRAPH_BASE}/security/runHuntingQuery"
LEGACY_DEFENDER_HUNTING_URL = "https://api.security.microsoft.com/api/advancedhunting/run"
PURVIEW_MANAGE_BASE = "https://manage.office.com/api/v1.0"

# All tables listed in Microsoft's Defender XDR advanced hunting schema as of
# 2026-04-13. Preview tables are intentionally included. A tenant can return an
# authorization/availability error for tables whose product, preview, integration,
# or RBAC requirement isn't enabled; those errors are recorded per table.
ALL_HUNTING_TABLES = (
    "AADSignInEventsBeta",
    "AADSpnSignInEventsBeta",
    "AgentsInfo",
    "AIAgentsInfo",
    "AlertEvidence",
    "AlertInfo",
    "BehaviorEntities",
    "BehaviorInfo",
    "CampaignInfo",
    "CloudAppEvents",
    "CloudAuditEvents",
    "CloudDnsEvents",
    "CloudPolicyEnforcementEvents",
    "CloudProcessEvents",
    "CloudStorageAggregatedEvents",
    "DataSecurityBehaviors",
    "DataSecurityEvents",
    "DeviceBaselineComplianceAssessment",
    "DeviceBaselineComplianceAssessmentKB",
    "DeviceBaselineComplianceProfiles",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceInfo",
    "DeviceLogonEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "DeviceTvmBrowserExtensions",
    "DeviceTvmBrowserExtensionsKB",
    "DeviceTvmCertificateInfo",
    "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering",
    "DeviceTvmInfoGatheringKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DisruptionAndResponseEvents",
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "EntraIdSignInEvents",
    "EntraIdSpnSignInEvents",
    "ExposureGraphEdges",
    "ExposureGraphNodes",
    "FileMaliciousContentInfo",
    "GraphApiAuditEvents",
    "IdentityAccountInfo",
    "IdentityDirectoryEvents",
    "IdentityEvents",
    "IdentityInfo",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "MessageEvents",
    "MessagePostDeliveryEvents",
    "MessageUrlInfo",
    "OAuthAppInfo",
    "UrlClickEvents",
)
DEFAULT_HUNTING_TABLES = ALL_HUNTING_TABLES

# The Management Activity API exposes exactly these five content types.
# Audit.General includes all workloads not represented by the first three audit feeds.
ALL_PURVIEW_CONTENT_TYPES = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All",
)
DEFAULT_PURVIEW_CONTENT_TYPES = ALL_PURVIEW_CONTENT_TYPES

ADVANCED_HUNTING_MAX_ROWS = 100_000

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime and normalize it to UTC."""
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_z(value: datetime, timespec: str = "seconds") -> str:
    return value.astimezone(timezone.utc).isoformat(timespec=timespec).replace("+00:00", "Z")


def kusto_datetime(value: datetime) -> str:
    return iso_z(value, timespec="microseconds")


def chunks(start: datetime, end: datetime, size: timedelta) -> Iterator[Tuple[datetime, datetime]]:
    cursor = start
    while cursor < end:
        chunk_end = min(cursor + size, end)
        yield cursor, chunk_end
        cursor = chunk_end


def json_hash(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def unique_records(records: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """De-duplicate audit records while preserving the first copy."""
    seen: set[str] = set()
    output: List[Dict[str, Any]] = []
    for record in records:
        record_id = record.get("Id") or record.get("id")
        if record_id:
            key = f"id:{record_id}"
        else:
            key = f"hash:{json_hash(record)}"
        if key in seen:
            continue
        seen.add(key)
        output.append(dict(record))
    return output


class CollectorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    tenant_id: str
    client_id: str
    client_secret: Optional[str]
    client_certificate_path: Optional[str]
    client_certificate_thumbprint: Optional[str]
    publisher_identifier: str

    @classmethod
    def from_environment(cls) -> "Settings":
        tenant_id = os.getenv("AZURE_TENANT_ID", "").strip()
        client_id = os.getenv("AZURE_CLIENT_ID", "").strip()
        client_secret = os.getenv("AZURE_CLIENT_SECRET", "").strip() or None
        certificate_path = os.getenv("AZURE_CLIENT_CERTIFICATE_PATH", "").strip() or None
        certificate_thumbprint = os.getenv("AZURE_CLIENT_CERTIFICATE_THUMBPRINT", "").strip() or None

        missing = []
        if not tenant_id:
            missing.append("AZURE_TENANT_ID")
        if not client_id:
            missing.append("AZURE_CLIENT_ID")
        if missing:
            raise CollectorError(f"Missing required environment variables: {', '.join(missing)}")

        has_certificate = bool(certificate_path and certificate_thumbprint)
        if not client_secret and not has_certificate:
            raise CollectorError(
                "Configure AZURE_CLIENT_SECRET, or configure both "
                "AZURE_CLIENT_CERTIFICATE_PATH and AZURE_CLIENT_CERTIFICATE_THUMBPRINT"
            )
        if bool(certificate_path) != bool(certificate_thumbprint):
            raise CollectorError(
                "AZURE_CLIENT_CERTIFICATE_PATH and AZURE_CLIENT_CERTIFICATE_THUMBPRINT "
                "must be configured together"
            )
        if certificate_path and not Path(certificate_path).expanduser().is_file():
            raise CollectorError(f"Certificate private-key file not found: {certificate_path}")

        publisher = os.getenv("PURVIEW_PUBLISHER_IDENTIFIER", "").strip() or tenant_id
        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            client_certificate_path=certificate_path,
            client_certificate_thumbprint=certificate_thumbprint,
            publisher_identifier=publisher,
        )


class TokenProvider:
    def __init__(self, settings: Settings) -> None:
        if settings.client_certificate_path and settings.client_certificate_thumbprint:
            private_key = Path(settings.client_certificate_path).expanduser().read_text(encoding="utf-8")
            credential: Any = {
                "private_key": private_key,
                "thumbprint": settings.client_certificate_thumbprint,
            }
        else:
            credential = settings.client_secret

        self._app = msal.ConfidentialClientApplication(
            client_id=settings.client_id,
            authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
            client_credential=credential,
        )
        self._cache: Dict[str, Tuple[str, float]] = {}

    def get(self, scope: str, force_refresh: bool = False) -> str:
        cached = self._cache.get(scope)
        if cached and not force_refresh and cached[1] > time.time() + 120:
            return cached[0]

        result = self._app.acquire_token_for_client(scopes=[scope])
        token = result.get("access_token")
        if not token:
            raise CollectorError(
                "Token acquisition failed for "
                f"{scope}: {result.get('error')} - {result.get('error_description')}"
            )

        expires_in = int(result.get("expires_in", 3599))
        self._cache[scope] = (token, time.time() + expires_in)
        return token


class ApiClient:
    def __init__(
        self,
        token_provider: TokenProvider,
        scope: str,
        timeout_seconds: int = 120,
        max_attempts: int = 7,
    ) -> None:
        self.token_provider = token_provider
        self.scope = scope
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "m365-security-exporter/1.0"})

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Any] = None,
        expected: Sequence[int] = (200,),
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        last_error: Optional[BaseException] = None
        refreshed_after_401 = False

        for attempt in range(1, self.max_attempts + 1):
            headers = {
                "Authorization": f"Bearer {self.token_provider.get(self.scope, force_refresh=False)}",
                "Accept": "application/json",
            }
            if json_body is not None:
                headers["Content-Type"] = "application/json"
            if extra_headers:
                headers.update(extra_headers)

            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                last_error = exc
                if attempt == self.max_attempts:
                    break
                sleep_seconds = min(60.0, (2 ** (attempt - 1)) + random.random())
                logging.warning("Request error for %s; retrying in %.1fs: %s", url, sleep_seconds, exc)
                time.sleep(sleep_seconds)
                continue

            if response.status_code in expected:
                return response

            if response.status_code == 401 and not refreshed_after_401:
                self.token_provider.get(self.scope, force_refresh=True)
                refreshed_after_401 = True
                continue

            if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_attempts:
                retry_after = response.headers.get("Retry-After")
                try:
                    sleep_seconds = float(retry_after) if retry_after else min(60.0, 2 ** (attempt - 1))
                except ValueError:
                    sleep_seconds = min(60.0, 2 ** (attempt - 1))
                sleep_seconds += random.random()
                logging.warning(
                    "HTTP %s for %s; retrying in %.1fs",
                    response.status_code,
                    url,
                    sleep_seconds,
                )
                time.sleep(sleep_seconds)
                continue

            body = response.text[:4000]
            raise CollectorError(f"HTTP {response.status_code} for {method} {url}: {body}")

        raise CollectorError(f"Request failed after retries for {method} {url}: {last_error}")

    def get_json(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        expected: Sequence[int] = (200,),
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> Tuple[Any, requests.Response]:
        response = self.request(
            "GET",
            url,
            params=params,
            expected=expected,
            extra_headers=extra_headers,
        )
        if response.status_code == 204 or not response.content:
            return None, response
        try:
            return response.json(), response
        except ValueError as exc:
            raise CollectorError(f"Expected JSON from {url}, received: {response.text[:1000]}") from exc

    def post_json(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Any] = None,
        expected: Sequence[int] = (200,),
    ) -> Tuple[Any, requests.Response]:
        response = self.request(
            "POST",
            url,
            params=params,
            json_body=json_body,
            expected=expected,
        )
        if response.status_code == 204 or not response.content:
            return None, response
        try:
            return response.json(), response
        except ValueError as exc:
            raise CollectorError(f"Expected JSON from {url}, received: {response.text[:1000]}") from exc


class GraphSecurityCollector:
    def __init__(self, client: ApiClient) -> None:
        self.client = client

    def _get_collection(self, path: str, params: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
        url = f"{GRAPH_BASE}{path}"
        output: List[Dict[str, Any]] = []
        next_params: Optional[Mapping[str, Any]] = params

        while url:
            payload, _ = self.client.get_json(url, params=next_params)
            next_params = None
            if not isinstance(payload, dict):
                raise CollectorError(f"Unexpected Graph collection response for {path}")
            values = payload.get("value", [])
            if not isinstance(values, list):
                raise CollectorError(f"Unexpected Graph value payload for {path}")
            output.extend(item for item in values if isinstance(item, dict))
            url = payload.get("@odata.nextLink") or ""
        return output

    def collect(self, start: datetime, end: datetime) -> Dict[str, Any]:
        graph_filter = f"createdDateTime ge {iso_z(start)} and createdDateTime lt {iso_z(end)}"
        incidents = self._get_collection(
            "/security/incidents",
            params={"$filter": graph_filter, "$top": "100"},
        )
        alerts = self._get_collection(
            "/security/alerts_v2",
            params={"$filter": graph_filter, "$top": "100"},
        )
        return {
            "incidents": incidents,
            "alerts": alerts,
            "counts": {"incidents": len(incidents), "alerts": len(alerts)},
        }


class AdvancedHuntingCollector:
    """Export every requested Defender XDR hunting table.

    The collector probes each table's schema. Tables with a Timestamp column are
    collected in time slices, with recursive splitting when a slice reaches the API
    row ceiling. Tables without Timestamp are collected as current entity/snapshot
    data with an explicit row ceiling and a truncation warning when that ceiling is hit.

    Microsoft Graph runHuntingQuery is preferred. In auto mode, the collector falls
    back once to the legacy Defender endpoint if the Graph permission isn't present.
    """

    def __init__(
        self,
        graph_client: ApiClient,
        legacy_client: ApiClient,
        chunk_hours: int,
        *,
        min_chunk_minutes: int = 5,
        max_rows: int = ADVANCED_HUNTING_MAX_ROWS,
        backend: str = "auto",
    ) -> None:
        if chunk_hours <= 0:
            raise CollectorError("--hunting-chunk-hours must be greater than zero")
        if min_chunk_minutes <= 0:
            raise CollectorError("--hunting-min-chunk-minutes must be greater than zero")
        if max_rows <= 0 or max_rows > ADVANCED_HUNTING_MAX_ROWS:
            raise CollectorError(
                f"--hunting-max-rows must be between 1 and {ADVANCED_HUNTING_MAX_ROWS}"
            )
        if backend not in {"auto", "graph", "legacy"}:
            raise CollectorError("--hunting-api must be auto, graph, or legacy")

        self.graph_client = graph_client
        self.legacy_client = legacy_client
        self.chunk_size = timedelta(hours=chunk_hours)
        self.min_chunk_size = timedelta(minutes=min_chunk_minutes)
        self.max_rows = max_rows
        self.requested_backend = backend
        self.selected_backend: Optional[str] = None if backend == "auto" else backend
        self.backend_probe_error: Optional[str] = None

    @staticmethod
    def _validate_table(table: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", table):
            raise CollectorError(f"Invalid Advanced Hunting table identifier: {table!r}")
        return table

    @staticmethod
    def _normalize_response(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise CollectorError("Unexpected Advanced Hunting response")
        rows = payload.get("results", payload.get("Results", []))
        schema = payload.get("schema", payload.get("Schema", []))
        stats = payload.get("stats", payload.get("Stats", {}))
        return {
            "results": rows if isinstance(rows, list) else [],
            "schema": schema if isinstance(schema, list) else [],
            "stats": stats,
            "raw": payload,
        }

    def _run_graph(self, query: str, start: Optional[datetime], end: Optional[datetime]) -> Dict[str, Any]:
        body: Dict[str, Any] = {"Query": query}
        if start is not None and end is not None:
            body["Timespan"] = f"{iso_z(start)}/{iso_z(end)}"
        payload, _ = self.graph_client.post_json(
            GRAPH_HUNTING_URL,
            json_body=body,
            expected=(200,),
        )
        return self._normalize_response(payload)

    def _run_legacy(self, query: str) -> Dict[str, Any]:
        payload, _ = self.legacy_client.post_json(
            LEGACY_DEFENDER_HUNTING_URL,
            json_body={"Query": query},
            expected=(200,),
        )
        return self._normalize_response(payload)

    def run_query(
        self,
        query: str,
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        if self.selected_backend == "graph":
            return self._run_graph(query, start, end)
        if self.selected_backend == "legacy":
            return self._run_legacy(query)

        # Auto mode: Graph is the current API. Fall back to the legacy endpoint so
        # existing apps with AdvancedHunting.Read.All continue to work until migration.
        try:
            response = self._run_graph(query, start, end)
            self.selected_backend = "graph"
            logging.info("Using Microsoft Graph runHuntingQuery for Advanced Hunting")
            return response
        except Exception as graph_exc:
            self.backend_probe_error = str(graph_exc)
            logging.warning(
                "Microsoft Graph Advanced Hunting failed; trying the legacy Defender endpoint: %s",
                graph_exc,
            )
            try:
                response = self._run_legacy(query)
                self.selected_backend = "legacy"
                logging.info("Using legacy Defender Advanced Hunting endpoint")
                return response
            except Exception as legacy_exc:
                raise CollectorError(
                    "Both Advanced Hunting APIs failed. Graph error: "
                    f"{graph_exc}; legacy error: {legacy_exc}"
                ) from legacy_exc

    @staticmethod
    def _schema_column_names(schema: Sequence[Any]) -> List[str]:
        names: List[str] = []
        for column in schema:
            if not isinstance(column, dict):
                continue
            name = column.get("name", column.get("Name"))
            if name:
                names.append(str(name))
        return names

    def probe_table_schema(self, table: str) -> Dict[str, Any]:
        response = self.run_query(f"{table}\n| take 0")
        schema = response.get("schema", [])
        column_names = self._schema_column_names(schema)
        return {
            "schema": schema,
            "column_names": column_names,
            "has_timestamp": any(name.casefold() == "timestamp" for name in column_names),
        }

    def _query_time_slice(
        self,
        table: str,
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:
        query = (
            f"{table}\n"
            f"| where Timestamp >= datetime({kusto_datetime(start)}) "
            f"and Timestamp < datetime({kusto_datetime(end)})\n"
            f"| take {self.max_rows}"
        )
        return self.run_query(query, start=start, end=end)

    def _collect_time_slice_recursive(
        self,
        table: str,
        start: datetime,
        end: datetime,
        rows: List[Dict[str, Any]],
        query_stats: List[Any],
        slices: List[Dict[str, Any]],
        errors: List[Dict[str, Any]],
    ) -> None:
        try:
            response = self._query_time_slice(table, start, end)
        except Exception as exc:
            logging.exception(
                "Advanced Hunting table %s failed for %s to %s",
                table,
                iso_z(start),
                iso_z(end),
            )
            errors.append(
                {
                    "stage": "time_slice",
                    "start": iso_z(start),
                    "end": iso_z(end),
                    "error": str(exc),
                }
            )
            return

        result_rows = [row for row in response.get("results", []) if isinstance(row, dict)]
        hit_limit = len(result_rows) >= self.max_rows
        duration = end - start

        if hit_limit and duration > self.min_chunk_size:
            midpoint = start + (duration / 2)
            logging.warning(
                "%s returned %d rows for %s to %s; splitting the interval",
                table,
                len(result_rows),
                iso_z(start),
                iso_z(end),
            )
            self._collect_time_slice_recursive(
                table, start, midpoint, rows, query_stats, slices, errors
            )
            self._collect_time_slice_recursive(
                table, midpoint, end, rows, query_stats, slices, errors
            )
            return

        rows.extend(result_rows)
        if response.get("stats") is not None:
            query_stats.append(response.get("stats"))
        slices.append(
            {
                "start": iso_z(start),
                "end": iso_z(end),
                "rows": len(result_rows),
                "hitRowLimit": hit_limit,
                "minimumSliceReached": bool(hit_limit and duration <= self.min_chunk_size),
            }
        )

    def collect_table(self, table: str, start: datetime, end: datetime) -> Dict[str, Any]:
        table = self._validate_table(table)
        output: Dict[str, Any] = {
            "results": [],
            "schema": [],
            "query_stats": [],
            "slices": [],
            "errors": [],
            "collection_mode": "unknown",
            "possible_truncation": False,
            "max_rows_per_query": self.max_rows,
        }

        try:
            schema_info = self.probe_table_schema(table)
            output["schema"] = schema_info["schema"]
            output["schema_columns"] = schema_info["column_names"]
        except Exception as exc:
            logging.exception("Advanced Hunting schema probe failed for %s", table)
            output["errors"].append({"stage": "schema_probe", "error": str(exc)})
            output["backend"] = self.selected_backend or self.requested_backend
            return output

        if schema_info["has_timestamp"]:
            output["collection_mode"] = "time_sliced"
            rows: List[Dict[str, Any]] = []
            stats: List[Any] = []
            slices_meta: List[Dict[str, Any]] = []
            errors: List[Dict[str, Any]] = []
            for chunk_start, chunk_end in chunks(start, end, self.chunk_size):
                self._collect_time_slice_recursive(
                    table,
                    chunk_start,
                    chunk_end,
                    rows,
                    stats,
                    slices_meta,
                    errors,
                )
            output["results"] = unique_records(rows)
            output["query_stats"] = stats
            output["slices"] = slices_meta
            output["errors"] = errors
            output["possible_truncation"] = any(
                item.get("minimumSliceReached") for item in slices_meta
            )
        else:
            output["collection_mode"] = "snapshot_or_entity"
            query = f"{table}\n| take {self.max_rows}"
            try:
                response = self.run_query(query)
                rows = [row for row in response.get("results", []) if isinstance(row, dict)]
                output["results"] = unique_records(rows)
                output["query_stats"] = [response.get("stats")]
                output["slices"] = [
                    {
                        "rows": len(rows),
                        "hitRowLimit": len(rows) >= self.max_rows,
                        "note": "Table has no Timestamp column; a current snapshot/entity export was used.",
                    }
                ]
                output["possible_truncation"] = len(rows) >= self.max_rows
            except Exception as exc:
                logging.exception("Advanced Hunting snapshot table %s failed", table)
                output["errors"].append({"stage": "snapshot_query", "error": str(exc)})

        output["backend"] = self.selected_backend or self.requested_backend
        output["count"] = len(output.get("results", []))
        return output

    def collect(self, tables: Sequence[str], start: datetime, end: datetime) -> Dict[str, Any]:
        collected: Dict[str, Any] = {}
        for position, table in enumerate(tables, start=1):
            logging.info(
                "Collecting Defender Advanced Hunting table %d/%d: %s",
                position,
                len(tables),
                table,
            )
            collected[table] = self.collect_table(table, start, end)
        return collected

def build_correlated_email_index(hunting: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Correlate email metadata from hunting tables by NetworkMessageId."""
    table_to_bucket = {
        "EmailEvents": "email_events",
        "EmailAttachmentInfo": "attachments",
        "EmailUrlInfo": "urls",
        "UrlClickEvents": "url_clicks",
        "EmailPostDeliveryEvents": "post_delivery_events",
    }
    index: Dict[str, Dict[str, Any]] = {}

    for table, bucket in table_to_bucket.items():
        table_data = hunting.get(table, {})
        rows = table_data.get("results", []) if isinstance(table_data, dict) else []
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            network_message_id = row.get("NetworkMessageId")
            if not network_message_id:
                continue
            item = index.setdefault(
                str(network_message_id),
                {
                    "networkMessageId": str(network_message_id),
                    "subjects": [],
                    "senders": [],
                    "recipients": [],
                    "attachmentNames": [],
                    "urlsFound": [],
                    "email_events": [],
                    "attachments": [],
                    "urls": [],
                    "url_clicks": [],
                    "post_delivery_events": [],
                },
            )
            item[bucket].append(row)

            for field, output_name in (
                ("Subject", "subjects"),
                ("SenderFromAddress", "senders"),
                ("SenderMailFromAddress", "senders"),
                ("RecipientEmailAddress", "recipients"),
                ("FileName", "attachmentNames"),
                ("Url", "urlsFound"),
                ("URL", "urlsFound"),
            ):
                value = row.get(field)
                if value not in (None, ""):
                    item[output_name].append(value)

    for item in index.values():
        for summary_field in ("subjects", "senders", "recipients", "attachmentNames", "urlsFound"):
            values = item.get(summary_field, [])
            item[summary_field] = list(dict.fromkeys(values))

    return sorted(index.values(), key=lambda item: item["networkMessageId"])


class PurviewAuditSearchCollector:
    """Collect the unified Microsoft Purview audit log through Microsoft Graph.

    This is separate from the near-real-time Office 365 Management Activity feed.
    It creates asynchronous audit searches, waits for completion, and downloads all
    paged records that the caller's AuditLogsQuery permissions and retention allow.
    """

    def __init__(
        self,
        client: ApiClient,
        *,
        chunk_days: int = 7,
        poll_seconds: int = 5,
        timeout_seconds: int = 900,
    ) -> None:
        if chunk_days <= 0 or chunk_days > 180:
            raise CollectorError("--purview-audit-chunk-days must be between 1 and 180")
        if poll_seconds <= 0:
            raise CollectorError("--purview-audit-poll-seconds must be greater than zero")
        if timeout_seconds <= 0:
            raise CollectorError("--purview-audit-timeout-seconds must be greater than zero")
        self.client = client
        self.chunk_size = timedelta(days=chunk_days)
        self.poll_seconds = poll_seconds
        self.timeout_seconds = timeout_seconds
        self.root = f"{GRAPH_BASE}/security/auditLog/queries"

    def create_query(self, start: datetime, end: datetime) -> Dict[str, Any]:
        display_name = (
            "m365-security-exporter-"
            f"{start.strftime('%Y%m%dT%H%M%SZ')}-"
            f"{end.strftime('%Y%m%dT%H%M%SZ')}"
        )
        payload, _ = self.client.post_json(
            self.root,
            json_body={
                "@odata.type": "#microsoft.graph.security.auditLogQuery",
                "displayName": display_name,
                "filterStartDateTime": iso_z(start),
                "filterEndDateTime": iso_z(end),
            },
            expected=(201,),
        )
        if not isinstance(payload, dict) or not payload.get("id"):
            raise CollectorError("Purview Audit Search API didn't return a query ID")
        return payload

    def get_query(self, query_id: str) -> Dict[str, Any]:
        payload, _ = self.client.get_json(f"{self.root}/{query_id}")
        if not isinstance(payload, dict):
            raise CollectorError(f"Unexpected Purview audit query response for {query_id}")
        return payload

    def wait_for_query(self, query_id: str) -> Dict[str, Any]:
        deadline = time.monotonic() + self.timeout_seconds
        last_status = "unknown"
        while time.monotonic() < deadline:
            query = self.get_query(query_id)
            last_status = str(query.get("status", "unknown")).casefold()
            if last_status == "succeeded":
                return query
            if last_status in {"failed", "cancelled"}:
                raise CollectorError(
                    f"Purview audit query {query_id} finished with status {last_status}: {query}"
                )
            time.sleep(self.poll_seconds)
        raise CollectorError(
            f"Timed out after {self.timeout_seconds}s waiting for Purview audit query "
            f"{query_id}; last status was {last_status}"
        )

    def list_records(self, query_id: str) -> List[Dict[str, Any]]:
        url = f"{self.root}/{query_id}/records"
        params: Optional[Mapping[str, Any]] = {"$top": "1000"}
        records: List[Dict[str, Any]] = []
        while url:
            payload, _ = self.client.get_json(url, params=params)
            params = None
            if not isinstance(payload, dict):
                raise CollectorError(f"Unexpected audit record response for query {query_id}")
            values = payload.get("value", [])
            if not isinstance(values, list):
                raise CollectorError(f"Unexpected audit record collection for query {query_id}")
            records.extend(item for item in values if isinstance(item, dict))
            url = str(payload.get("@odata.nextLink") or "")
        return records

    def collect_window(self, start: datetime, end: datetime) -> Dict[str, Any]:
        created = self.create_query(start, end)
        query_id = str(created["id"])
        completed = self.wait_for_query(query_id)
        records = self.list_records(query_id)
        deduplicated = unique_records(records)
        return {
            "window": {"start": iso_z(start), "end": iso_z(end)},
            "query": completed,
            "records": deduplicated,
            "counts": {
                "records_before_deduplication": len(records),
                "records": len(deduplicated),
            },
        }

    def collect(self, start: datetime, end: datetime) -> Dict[str, Any]:
        windows: List[Dict[str, Any]] = []
        all_records: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        for window_start, window_end in chunks(start, end, self.chunk_size):
            logging.info(
                "Collecting Purview Audit Search records: %s to %s",
                iso_z(window_start),
                iso_z(window_end),
            )
            try:
                result = self.collect_window(window_start, window_end)
                windows.append(
                    {
                        "window": result["window"],
                        "query": result["query"],
                        "counts": result["counts"],
                    }
                )
                all_records.extend(result["records"])
            except Exception as exc:
                logging.exception("Purview Audit Search failed")
                errors.append(
                    {
                        "start": iso_z(window_start),
                        "end": iso_z(window_end),
                        "error": str(exc),
                    }
                )

        deduplicated = unique_records(all_records)
        return {
            "windows": windows,
            "records": deduplicated,
            "counts": {
                "windows": len(windows),
                "records_before_deduplication": len(all_records),
                "records": len(deduplicated),
            },
            "errors": errors,
        }


class PurviewActivityCollector:
    def __init__(self, client: ApiClient, settings: Settings) -> None:
        self.client = client
        self.settings = settings
        self.root = f"{PURVIEW_MANAGE_BASE}/{settings.tenant_id}/activity/feed"

    @property
    def common_params(self) -> Dict[str, str]:
        return {"PublisherIdentifier": self.settings.publisher_identifier}

    def list_subscriptions(self) -> List[Dict[str, Any]]:
        payload, _ = self.client.get_json(
            f"{self.root}/subscriptions/list",
            params=self.common_params,
        )
        if not isinstance(payload, list):
            raise CollectorError("Unexpected Purview subscriptions response")
        return [item for item in payload if isinstance(item, dict)]

    def start_subscription(self, content_type: str) -> Dict[str, Any]:
        params = dict(self.common_params)
        params["contentType"] = content_type
        payload, _ = self.client.post_json(
            f"{self.root}/subscriptions/start",
            params=params,
            json_body=None,
            expected=(200,),
        )
        return payload if isinstance(payload, dict) else {"contentType": content_type, "status": "enabled"}

    def list_content(
        self,
        content_type: str,
        start: datetime,
        end: datetime,
    ) -> List[Dict[str, Any]]:
        params: Optional[Dict[str, str]] = dict(self.common_params)
        params.update(
            {
                "contentType": content_type,
                "startTime": iso_z(start),
                "endTime": iso_z(end),
            }
        )
        url = f"{self.root}/subscriptions/content"
        blobs: List[Dict[str, Any]] = []

        while url:
            payload, response = self.client.get_json(url, params=params)
            params = None
            if not isinstance(payload, list):
                raise CollectorError(f"Unexpected Purview content list for {content_type}")
            blobs.extend(item for item in payload if isinstance(item, dict))
            url = response.headers.get("NextPageUri", "")

        return blobs

    def retrieve_blob(self, content_uri: str) -> List[Dict[str, Any]]:
        parsed = urlparse(content_uri)
        if parsed.scheme != "https" or parsed.hostname not in {
            "manage.office.com",
            "manage-gcc.office.com",
            "manage.office365.us",
            "manage.protection.apps.mil",
        }:
            raise CollectorError(f"Refusing unexpected Purview content URI: {content_uri}")

        payload, _ = self.client.get_json(content_uri)
        if not isinstance(payload, list):
            raise CollectorError(f"Unexpected Purview blob response from {content_uri}")
        return [item for item in payload if isinstance(item, dict)]

    def get_dlp_sensitive_types(self) -> List[Dict[str, Any]]:
        payload, _ = self.client.get_json(
            f"{self.root}/resources/dlpSensitiveTypes",
            params=self.common_params,
        )
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    def collect_content_type(self, content_type: str, start: datetime, end: datetime) -> Dict[str, Any]:
        blobs: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        # API requires windows of 24 hours or less and supports content made available
        # no more than seven days in the past.
        for window_start, window_end in chunks(start, end, timedelta(hours=24)):
            try:
                listed = self.list_content(content_type, window_start, window_end)
                blobs.extend(listed)
            except Exception as exc:
                logging.exception("Purview content listing failed for %s", content_type)
                errors.append(
                    {
                        "stage": "list_content",
                        "start": iso_z(window_start),
                        "end": iso_z(window_end),
                        "error": str(exc),
                    }
                )
                continue

        # De-duplicate content blobs before download.
        unique_blobs: Dict[str, Dict[str, Any]] = {}
        for blob in blobs:
            key = str(blob.get("contentId") or blob.get("contentUri") or json_hash(blob))
            unique_blobs[key] = blob

        for blob in unique_blobs.values():
            content_uri = blob.get("contentUri")
            if not content_uri:
                continue
            try:
                events.extend(self.retrieve_blob(str(content_uri)))
            except Exception as exc:
                logging.exception("Purview content download failed: %s", content_uri)
                errors.append(
                    {
                        "stage": "retrieve_blob",
                        "contentId": blob.get("contentId"),
                        "contentUri": content_uri,
                        "error": str(exc),
                    }
                )

        deduplicated_events = unique_records(events)
        return {
            "blobs": list(unique_blobs.values()),
            "events": deduplicated_events,
            "counts": {
                "blobs": len(unique_blobs),
                "events_before_deduplication": len(events),
                "events": len(deduplicated_events),
            },
            "errors": errors,
        }

    def collect(self, content_types: Sequence[str], start: datetime, end: datetime) -> Dict[str, Any]:
        subscriptions = self.list_subscriptions()
        enabled = {
            str(item.get("contentType"))
            for item in subscriptions
            if str(item.get("status", "")).lower() == "enabled"
        }

        data: Dict[str, Any] = {
            "subscriptions": subscriptions,
            "content_types": {},
            "dlp_sensitive_types": [],
        }

        try:
            data["dlp_sensitive_types"] = self.get_dlp_sensitive_types()
        except Exception as exc:
            data["dlp_sensitive_types_error"] = str(exc)

        for content_type in content_types:
            if content_type not in enabled:
                data["content_types"][content_type] = {
                    "blobs": [],
                    "events": [],
                    "counts": {"blobs": 0, "events_before_deduplication": 0, "events": 0},
                    "errors": [
                        {
                            "stage": "subscription",
                            "error": (
                                f"Subscription {content_type} is not enabled. "
                                f"Run: python collector.py --start-subscription {content_type}"
                            ),
                        }
                    ],
                }
                continue

            logging.info("Collecting Purview content type: %s", content_type)
            data["content_types"][content_type] = self.collect_content_type(content_type, start, end)

        return data


def add_error(result: MutableMapping[str, Any], source: str, exc: BaseException) -> None:
    result.setdefault("errors", []).append({"source": source, "error": str(exc)})
    logging.exception("Collection failed for %s", source)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export Microsoft Defender XDR and Microsoft Purview audit/DLP data to JSON."
    )
    parser.add_argument("--days", type=float, default=1.0, help="Look-back window in days. Default: 1")
    parser.add_argument("--start", help="UTC/ISO start time. Overrides --days when used with --end.")
    parser.add_argument("--end", help="UTC/ISO end time. Defaults to now.")
    parser.add_argument(
        "--output",
        default=f"m365-security-export-{utc_now().strftime('%Y%m%dT%H%M%SZ')}.json",
        help="Output JSON path.",
    )
    parser.add_argument(
        "--hunting-table",
        action="append",
        dest="hunting_tables",
        help="Advanced Hunting table to export. Repeatable. Defaults to every documented XDR table.",
    )
    parser.add_argument(
        "--purview-content-type",
        action="append",
        dest="purview_content_types",
        help="Purview activity content type. Repeatable.",
    )
    parser.add_argument(
        "--hunting-chunk-hours",
        type=int,
        default=6,
        help="Initial Advanced Hunting time chunk size. Default: 6 hours.",
    )
    parser.add_argument(
        "--hunting-min-chunk-minutes",
        type=int,
        default=5,
        help="Smallest recursive time slice when a hunting query hits the row ceiling. Default: 5.",
    )
    parser.add_argument(
        "--hunting-max-rows",
        type=int,
        default=ADVANCED_HUNTING_MAX_ROWS,
        help=f"Maximum rows requested per hunting query. Max/default: {ADVANCED_HUNTING_MAX_ROWS}.",
    )
    parser.add_argument(
        "--hunting-api",
        choices=("auto", "graph", "legacy"),
        default="auto",
        help=(
            "Advanced Hunting API. auto prefers Microsoft Graph and falls back to the legacy "
            "Defender endpoint. Default: auto."
        ),
    )
    parser.add_argument("--skip-graph-security", action="store_true", help="Skip Graph incidents/alerts.")
    parser.add_argument("--skip-hunting", action="store_true", help="Skip Defender Advanced Hunting.")
    parser.add_argument(
        "--skip-purview",
        action="store_true",
        help="Skip both Purview Audit Search and the Management Activity feed.",
    )
    parser.add_argument(
        "--skip-purview-audit-search",
        action="store_true",
        help="Skip the Microsoft Graph Purview Audit Search API.",
    )
    parser.add_argument(
        "--skip-purview-activity-feed",
        action="store_true",
        help="Skip the Office 365 Management Activity API feed.",
    )
    parser.add_argument(
        "--purview-audit-chunk-days",
        type=int,
        default=7,
        help="Purview Audit Search query window size, 1-180 days. Default: 7.",
    )
    parser.add_argument(
        "--purview-audit-poll-seconds",
        type=int,
        default=5,
        help="Seconds between Purview Audit Search status checks. Default: 5.",
    )
    parser.add_argument(
        "--purview-audit-timeout-seconds",
        type=int,
        default=900,
        help="Maximum wait per Purview Audit Search query. Default: 900.",
    )
    parser.add_argument(
        "--start-subscription",
        action="append",
        help=(
            "Enable one Purview content subscription and exit. Repeatable, but Microsoft recommends "
            "waiting 15 minutes between subscription-start requests."
        ),
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON with indentation.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def resolve_window(args: argparse.Namespace) -> Tuple[datetime, datetime]:
    end = parse_datetime(args.end) if args.end else utc_now()
    if args.start:
        start = parse_datetime(args.start)
    else:
        start = end - timedelta(days=args.days)
    if start >= end:
        raise CollectorError("Start time must be before end time")
    return start, end


def main() -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        settings = Settings.from_environment()
        start, end = resolve_window(args)
    except Exception as exc:
        logging.error("Configuration error: %s", exc)
        return 2

    token_provider = TokenProvider(settings)
    graph_client = ApiClient(token_provider, GRAPH_SCOPE)
    defender_client = ApiClient(token_provider, DEFENDER_SCOPE, timeout_seconds=210)
    purview_client = ApiClient(token_provider, PURVIEW_SCOPE)

    purview_collector = PurviewActivityCollector(purview_client, settings)
    if args.start_subscription:
        results: List[Dict[str, Any]] = []
        for content_type in args.start_subscription:
            try:
                results.append(purview_collector.start_subscription(content_type))
            except Exception as exc:
                results.append({"contentType": content_type, "error": str(exc)})
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0 if not any("error" in item for item in results) else 1

    result: Dict[str, Any] = {
        "generatedAt": iso_z(utc_now()),
        "tenantId": settings.tenant_id,
        "window": {"start": iso_z(start), "end": iso_z(end)},
        "xdr": {},
        "purview": {},
        "errors": [],
        "notes": [
            "Raw fields returned by Microsoft APIs are preserved.",
            "All currently documented Microsoft Defender XDR Advanced Hunting tables are requested by default, including preview and Purview-backed tables.",
            "Defender Advanced Hunting normally retains up to 30 days of raw data and caps each API query at 100,000 rows and a result-size limit.",
            "Snapshot/entity hunting tables without Timestamp are exported with a single capped query and are marked possible_truncation when the row ceiling is reached.",
            "Purview Audit Search retrieves unified audit records allowed by tenant retention and AuditLogsQuery permissions.",
            "The Purview Management Activity API exposes exactly five content types and can list content made available during only the last 7 days.",
            "Purview Data Explorer and Content Explorer do not expose a universal bulk-export API; DataSecurityEvents, DataSecurityBehaviors, unified audit records, and DLP activity are the supported programmatic paths used here.",
        ],
    }

    if not args.skip_graph_security:
        try:
            result["xdr"]["graph_security"] = GraphSecurityCollector(graph_client).collect(start, end)
        except Exception as exc:
            add_error(result, "xdr.graph_security", exc)

    hunting_tables = tuple(dict.fromkeys(args.hunting_tables or DEFAULT_HUNTING_TABLES))
    if not args.skip_hunting:
        try:
            hunting_collector = AdvancedHuntingCollector(
                graph_client,
                defender_client,
                args.hunting_chunk_hours,
                min_chunk_minutes=args.hunting_min_chunk_minutes,
                max_rows=args.hunting_max_rows,
                backend=args.hunting_api,
            )
            hunting = hunting_collector.collect(hunting_tables, start, end)
            result["xdr"]["advanced_hunting"] = hunting
            result["xdr"]["advanced_hunting_metadata"] = {
                "requestedTables": list(hunting_tables),
                "requestedTableCount": len(hunting_tables),
                "selectedApi": hunting_collector.selected_backend,
                "graphFallbackReason": hunting_collector.backend_probe_error,
            }
            result["xdr"]["correlated_emails"] = build_correlated_email_index(hunting)
            result["xdr"]["correlated_email_count"] = len(result["xdr"]["correlated_emails"])
        except Exception as exc:
            add_error(result, "xdr.advanced_hunting", exc)

    purview_content_types = tuple(
        dict.fromkeys(args.purview_content_types or DEFAULT_PURVIEW_CONTENT_TYPES)
    )
    if not args.skip_purview:
        result["purview"]["requestedWindow"] = {"start": iso_z(start), "end": iso_z(end)}

        if not args.skip_purview_audit_search:
            try:
                audit_search_collector = PurviewAuditSearchCollector(
                    graph_client,
                    chunk_days=args.purview_audit_chunk_days,
                    poll_seconds=args.purview_audit_poll_seconds,
                    timeout_seconds=args.purview_audit_timeout_seconds,
                )
                result["purview"]["audit_search"] = audit_search_collector.collect(start, end)
            except Exception as exc:
                add_error(result, "purview.audit_search", exc)

        if not args.skip_purview_activity_feed:
            purview_start = max(start, end - timedelta(days=7))
            result["purview"]["effectiveActivityFeedWindow"] = {
                "start": iso_z(purview_start),
                "end": iso_z(end),
            }
            if purview_start > start:
                result["purview"]["activityFeedWindowWarning"] = (
                    "Purview activity feed retrieval was capped to seven days because older content "
                    "blobs cannot be listed or downloaded through this API."
                )
            try:
                result["purview"]["activity_feed"] = purview_collector.collect(
                    purview_content_types, purview_start, end
                )
            except Exception as exc:
                add_error(result, "purview.activity_feed", exc)

    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(
            result,
            handle,
            indent=2 if args.pretty else None,
            separators=None if args.pretty else (",", ":"),
            ensure_ascii=False,
            default=str,
        )
        handle.write("\n")

    logging.info("Export written to %s", output_path)
    logging.info("Top-level collection errors: %d", len(result.get("errors", [])))
    return 0 if not result.get("errors") else 1


if __name__ == "__main__":
    sys.exit(main())
