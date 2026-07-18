#!/usr/bin/env python3
"""Export Microsoft Defender XDR and Microsoft Purview activity data to JSON.

Data sources:
1. Microsoft Graph Security API
   - /security/incidents
   - /security/alerts_v2
2. Microsoft Defender XDR Advanced Hunting API
   - All 64 tables currently documented in the Defender XDR hunting schema
   - Event tables are time-sliced; snapshot tables are queried without Timestamp filters
3. Office 365 Management Activity API (Microsoft Purview audit/DLP feed)
   - Audit.AzureActiveDirectory
   - Audit.Exchange
   - Audit.SharePoint
   - Audit.General
   - DLP.All

The exporter preserves raw API fields and also builds a correlated email index keyed
by NetworkMessageId, which makes subjects, attachment names, URLs, recipients, and
post-delivery actions easier to consume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
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
DEFENDER_HUNTING_URL = "https://api.security.microsoft.com/api/advancedhunting/run"
PURVIEW_MANAGE_BASE = "https://manage.office.com/api/v1.0"

# Microsoft Defender XDR Advanced Hunting schema tables documented by Microsoft
# as of 2026-04-13. Availability still depends on tenant licensing and enabled products.
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
HUNTING_MAX_ROWS_PER_QUERY = 100_000
HUNTING_MIN_SLICE = timedelta(minutes=1)

DEFAULT_PURVIEW_CONTENT_TYPES = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All",
)

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
            params={"$filter": graph_filter, "$top": "50"},
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
    def __init__(self, client: ApiClient, chunk_hours: int) -> None:
        self.client = client
        self.chunk_size = timedelta(hours=chunk_hours)

    def run_query(self, query: str) -> Dict[str, Any]:
        payload, _ = self.client.post_json(
            DEFENDER_HUNTING_URL,
            json_body={"Query": query},
            expected=(200,),
        )
        if not isinstance(payload, dict):
            raise CollectorError("Unexpected Advanced Hunting response")
        return payload

    @staticmethod
    def _schema_column_names(schema: Any) -> set[str]:
        names: set[str] = set()
        if not isinstance(schema, list):
            return names
        for column in schema:
            if not isinstance(column, dict):
                continue
            name = column.get("Name") or column.get("name") or column.get("ColumnName")
            if name:
                names.add(str(name))
        return names

    def _inspect_table(self, table: str) -> Tuple[List[Any], bool]:
        # A zero-row query returns the table schema without exporting data. This lets
        # us distinguish event tables from inventory/snapshot tables that do not have
        # a Timestamp column.
        response = self.run_query(f"{table}\n| take 0")
        schema = response.get("Schema", [])
        return schema if isinstance(schema, list) else [], "Timestamp" in self._schema_column_names(schema)

    def _collect_timestamp_slice(
        self,
        table: str,
        start: datetime,
        end: datetime,
        depth: int = 0,
    ) -> Tuple[List[Dict[str, Any]], List[Any], List[Any], List[Dict[str, Any]], bool]:
        query = (
            f"{table}\n"
            f"| where Timestamp >= datetime({kusto_datetime(start)}) "
            f"and Timestamp < datetime({kusto_datetime(end)})"
        )
        response = self.run_query(query)
        raw_rows = response.get("Results", [])
        rows = [row for row in raw_rows if isinstance(row, dict)] if isinstance(raw_rows, list) else []
        schema = response.get("Schema", [])
        stats = response.get("Stats")
        hit_limit = len(rows) >= HUNTING_MAX_ROWS_PER_QUERY
        duration = end - start

        # Advanced Hunting has a 100,000-row result ceiling. Split busy time windows
        # recursively to reduce data loss. There is no generic cursor for this API.
        if hit_limit and duration > HUNTING_MIN_SLICE:
            midpoint = start + duration / 2
            left = self._collect_timestamp_slice(table, start, midpoint, depth + 1)
            right = self._collect_timestamp_slice(table, midpoint, end, depth + 1)
            return (
                left[0] + right[0],
                left[1] or right[1],
                left[2] + right[2],
                left[3] + right[3],
                left[4] or right[4],
            )

        slice_info = {
            "start": iso_z(start),
            "end": iso_z(end),
            "rows": len(rows),
            "hitRowLimit": hit_limit,
            "minimumSliceReached": bool(hit_limit and duration <= HUNTING_MIN_SLICE),
            "splitDepth": depth,
        }
        return (
            rows,
            schema if isinstance(schema, list) else [],
            [stats] if stats is not None else [],
            [slice_info],
            bool(hit_limit and duration <= HUNTING_MIN_SLICE),
        )

    def collect_table(self, table: str, start: datetime, end: datetime) -> Dict[str, Any]:
        try:
            probe_schema, has_timestamp = self._inspect_table(table)
        except Exception as exc:
            logging.exception("Advanced Hunting table %s schema probe failed", table)
            return {
                "collection_mode": "unavailable",
                "results": [],
                "schema": [],
                "query_stats": [],
                "slices": [],
                "possible_truncation": False,
                "errors": [{"error": str(exc)}],
            }

        if not has_timestamp:
            try:
                response = self.run_query(f"{table}\n| take {HUNTING_MAX_ROWS_PER_QUERY}")
                raw_rows = response.get("Results", [])
                rows = [row for row in raw_rows if isinstance(row, dict)] if isinstance(raw_rows, list) else []
                schema = response.get("Schema", probe_schema)
                possible_truncation = len(rows) >= HUNTING_MAX_ROWS_PER_QUERY
                return {
                    "collection_mode": "snapshot",
                    "results": rows,
                    "schema": schema if isinstance(schema, list) else probe_schema,
                    "query_stats": [response.get("Stats")] if response.get("Stats") is not None else [],
                    "slices": [],
                    "possible_truncation": possible_truncation,
                    "errors": [],
                    "note": (
                        "This table has no Timestamp column and was queried as a current snapshot. "
                        "Snapshot tables cannot be generically paginated through Advanced Hunting."
                    ),
                }
            except Exception as exc:
                logging.exception("Advanced Hunting snapshot table %s failed", table)
                return {
                    "collection_mode": "snapshot",
                    "results": [],
                    "schema": probe_schema,
                    "query_stats": [],
                    "slices": [],
                    "possible_truncation": False,
                    "errors": [{"error": str(exc)}],
                }

        all_results: List[Dict[str, Any]] = []
        schema: List[Any] = probe_schema
        stats: List[Any] = []
        slices: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        possible_truncation = False

        for chunk_start, chunk_end in chunks(start, end, self.chunk_size):
            try:
                rows, chunk_schema, chunk_stats, chunk_slices, chunk_truncated = (
                    self._collect_timestamp_slice(table, chunk_start, chunk_end)
                )
                all_results.extend(rows)
                if chunk_schema:
                    schema = chunk_schema
                stats.extend(chunk_stats)
                slices.extend(chunk_slices)
                possible_truncation = possible_truncation or chunk_truncated
            except Exception as exc:
                logging.exception("Advanced Hunting table %s failed", table)
                errors.append({
                    "start": iso_z(chunk_start),
                    "end": iso_z(chunk_end),
                    "error": str(exc),
                })

        return {
            "collection_mode": "time_sliced",
            "results": all_results,
            "schema": schema,
            "query_stats": stats,
            "slices": slices,
            "possible_truncation": possible_truncation,
            "errors": errors,
        }

    def collect(self, tables: Sequence[str], start: datetime, end: datetime) -> Dict[str, Any]:
        collected: Dict[str, Any] = {}
        for table in tables:
            logging.info("Collecting Defender Advanced Hunting table: %s", table)
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
        help="Advanced Hunting table to export. Repeatable. Defaults to alert/email tables.",
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
        help="Advanced Hunting query chunk size. Default: 6 hours.",
    )
    parser.add_argument("--skip-graph-security", action="store_true", help="Skip Graph incidents/alerts.")
    parser.add_argument("--skip-hunting", action="store_true", help="Skip Defender Advanced Hunting.")
    parser.add_argument("--skip-purview", action="store_true", help="Skip Purview activity feed.")
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
            "Defender Advanced Hunting normally retains up to 30 days of raw data.",
            "The Purview Management Activity API can list content made available during only the last 7 days.",
            "Purview Data Explorer and Content Explorer do not expose a universal bulk-export API; this export uses the unified audit/DLP activity feed that powers many Activity Explorer scenarios.",
        ],
    }

    if not args.skip_graph_security:
        try:
            result["xdr"]["graph_security"] = GraphSecurityCollector(graph_client).collect(start, end)
        except Exception as exc:
            add_error(result, "xdr.graph_security", exc)

    hunting_tables = tuple(args.hunting_tables or DEFAULT_HUNTING_TABLES)
    if not args.skip_hunting:
        try:
            hunting = AdvancedHuntingCollector(defender_client, args.hunting_chunk_hours).collect(
                hunting_tables, start, end
            )
            result["xdr"]["advanced_hunting"] = hunting
            result["xdr"]["correlated_emails"] = build_correlated_email_index(hunting)
            result["xdr"]["correlated_email_count"] = len(result["xdr"]["correlated_emails"])
        except Exception as exc:
            add_error(result, "xdr.advanced_hunting", exc)

    purview_content_types = tuple(args.purview_content_types or DEFAULT_PURVIEW_CONTENT_TYPES)
    if not args.skip_purview:
        purview_start = max(start, end - timedelta(days=7))
        result["purview"]["requestedWindow"] = {"start": iso_z(start), "end": iso_z(end)}
        result["purview"]["effectiveActivityFeedWindow"] = {
            "start": iso_z(purview_start),
            "end": iso_z(end),
        }
        if purview_start > start:
            result["purview"]["windowWarning"] = (
                "Purview activity feed retrieval was capped to seven days because older content blobs "
                "cannot be listed or downloaded through this API."
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
