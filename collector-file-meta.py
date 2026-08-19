#!/usr/bin/env python3
"""Export Microsoft Defender XDR and Microsoft Purview activity data to JSON.

Data sources:
1. Microsoft Graph Security API
   - /security/incidents
   - /security/alerts_v2
2. Microsoft Defender XDR Advanced Hunting API
   - AlertInfo, AlertEvidence
   - DeviceFileEvents plus SHA-1-to-SHA-256 FileProfile enrichment
   - EmailEvents, EmailAttachmentInfo, EmailUrlInfo
   - UrlClickEvents, EmailPostDeliveryEvents
3. Office 365 Management Activity API (Microsoft Purview audit/DLP feed)
   - Audit.AzureActiveDirectory
   - Audit.Exchange
   - Audit.SharePoint
   - Audit.General
   - DLP.All

The exporter preserves raw API fields and also builds:
- a correlated email index keyed by NetworkMessageId
- a resolved device-file SHA-256 index, using DeviceFileEvents.SHA256 when present
  and FileProfile(SHA1) enrichment when the raw SHA-256 field is empty
- a Purview SHA-256 index for hashes present anywhere in downloaded audit/DLP records
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

DEFAULT_HUNTING_TABLES = (
    "AlertInfo",
    "AlertEvidence",
    "DeviceFileEvents",
    "EmailEvents",
    "EmailAttachmentInfo",
    "EmailUrlInfo",
    "UrlClickEvents",
    "EmailPostDeliveryEvents",
)

DEFAULT_PURVIEW_CONTENT_TYPES = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All",
)

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

DEVICE_FILE_EVENT_TABLES = (
    "DeviceFileEvents",
    "DeviceEvents",
    "DeviceProcessEvents",
)



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


def normalize_hex_hash(value: Any, expected_length: int) -> Optional[str]:
    """Return a lowercase hexadecimal hash, or None when the value is invalid."""
    if value in (None, ""):
        return None
    candidate = str(value).strip().lower()
    if len(candidate) != expected_length:
        return None
    if any(character not in "0123456789abcdef" for character in candidate):
        return None
    return candidate


def extract_sha256_values(value: Any) -> List[str]:
    """Recursively find SHA-256 values in a raw Microsoft API record."""
    found: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            normalized_keys = {
                str(key).lower().replace("_", "").replace("-", ""): key
                for key in item
            }

            # Common shapes:
            #   {"SHA256": "..."}
            #   {"Algorithm": "SHA256", "Value": "..."}
            sha_key = normalized_keys.get("sha256")
            if sha_key is not None:
                sha_value = item.get(sha_key)
                if isinstance(sha_value, (list, tuple, set)):
                    for nested in sha_value:
                        normalized = normalize_hex_hash(nested, 64)
                        if normalized:
                            found.add(normalized)
                else:
                    normalized = normalize_hex_hash(sha_value, 64)
                    if normalized:
                        found.add(normalized)

            algorithm_key = normalized_keys.get("algorithm")
            value_key = normalized_keys.get("value")
            if algorithm_key is not None and value_key is not None:
                algorithm = str(item.get(algorithm_key, "")).replace("-", "").upper()
                if algorithm == "SHA256":
                    normalized = normalize_hex_hash(item.get(value_key), 64)
                    if normalized:
                        found.add(normalized)

            for nested in item.values():
                walk(nested)
        elif isinstance(item, (list, tuple, set)):
            for nested in item:
                walk(nested)

    walk(value)
    return sorted(found)


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
    def __init__(
        self,
        client: ApiClient,
        chunk_hours: int,
        *,
        enable_file_profile: bool = True,
        file_profile_limit: int = 1000,
    ) -> None:
        if not 1 <= file_profile_limit <= 1000:
            raise CollectorError("--file-profile-limit must be between 1 and 1000")
        self.client = client
        self.chunk_size = timedelta(hours=chunk_hours)
        self.enable_file_profile = enable_file_profile
        self.file_profile_limit = file_profile_limit

    def run_query(self, query: str) -> Dict[str, Any]:
        payload, _ = self.client.post_json(
            DEFENDER_HUNTING_URL,
            json_body={"Query": query},
            expected=(200,),
        )
        if not isinstance(payload, dict):
            raise CollectorError("Unexpected Advanced Hunting response")
        return payload

    def collect_table(self, table: str, start: datetime, end: datetime) -> Dict[str, Any]:
        all_results: List[Dict[str, Any]] = []
        schemas: List[Any] = []
        stats: List[Any] = []
        errors: List[Dict[str, Any]] = []

        for chunk_start, chunk_end in chunks(start, end, self.chunk_size):
            query = (
                f"{table}\n"
                f"| where Timestamp >= datetime({kusto_datetime(chunk_start)}) "
                f"and Timestamp < datetime({kusto_datetime(chunk_end)})"
            )
            try:
                response = self.run_query(query)
                rows = response.get("Results", [])
                if isinstance(rows, list):
                    all_results.extend(row for row in rows if isinstance(row, dict))
                if response.get("Schema") is not None:
                    schemas.append(response.get("Schema"))
                if response.get("Stats") is not None:
                    stats.append(response.get("Stats"))
            except Exception as exc:  # Keep other tables flowing if one isn't licensed/available.
                logging.exception("Advanced Hunting table %s failed", table)
                errors.append(
                    {
                        "start": iso_z(chunk_start),
                        "end": iso_z(chunk_end),
                        "error": str(exc),
                    }
                )

        return {
            "results": unique_records(all_results),
            "schema": schemas[0] if schemas else [],
            "query_stats": stats,
            "errors": errors,
        }

    def collect_file_profiles(self, start: datetime, end: datetime) -> Dict[str, Any]:
        """Resolve missing DeviceFileEvents SHA-256 values from SHA-1 using FileProfile()."""
        profiles_by_sha1: Dict[str, Dict[str, Any]] = {}
        schemas: List[Any] = []
        stats: List[Any] = []
        errors: List[Dict[str, Any]] = []

        for chunk_start, chunk_end in chunks(start, end, self.chunk_size):
            query = (
                "DeviceFileEvents\n"
                f"| where Timestamp >= datetime({kusto_datetime(chunk_start)}) "
                f"and Timestamp < datetime({kusto_datetime(chunk_end)})\n"
                "| where isnotempty(SHA1) and isempty(SHA256)\n"
                "| summarize LastSeen=max(Timestamp) by SHA1\n"
                f"| top {self.file_profile_limit} by LastSeen desc\n"
                "| project SHA1\n"
                f'| invoke FileProfile("SHA1", {self.file_profile_limit})\n'
                "| project SHA1, SHA256, MD5, FileSize, GlobalPrevalence, "
                "GlobalFirstSeen, SoftwareName, ProfileAvailability"
            )
            try:
                response = self.run_query(query)
                rows = response.get("Results", [])
                if isinstance(rows, list):
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        sha1 = normalize_hex_hash(row.get("SHA1"), 40)
                        if not sha1:
                            continue
                        normalized = dict(row)
                        normalized["SHA1"] = sha1
                        sha256 = normalize_hex_hash(row.get("SHA256"), 64)
                        if sha256:
                            normalized["SHA256"] = sha256
                        existing = profiles_by_sha1.get(sha1)
                        if existing is None or (
                            not normalize_hex_hash(existing.get("SHA256"), 64) and sha256
                        ):
                            profiles_by_sha1[sha1] = normalized
                if response.get("Schema") is not None:
                    schemas.append(response.get("Schema"))
                if response.get("Stats") is not None:
                    stats.append(response.get("Stats"))
            except Exception as exc:
                logging.exception("DeviceFileEvents FileProfile enrichment failed")
                errors.append(
                    {
                        "start": iso_z(chunk_start),
                        "end": iso_z(chunk_end),
                        "error": str(exc),
                    }
                )

        results = sorted(profiles_by_sha1.values(), key=lambda item: item.get("SHA1", ""))
        return {
            "results": results,
            "schema": schemas[0] if schemas else [],
            "query_stats": stats,
            "counts": {
                "profiles": len(results),
                "profiles_with_sha256": sum(
                    1 for row in results if normalize_hex_hash(row.get("SHA256"), 64)
                ),
            },
            "errors": errors,
            "notes": [
                "FileProfile enrichment is limited to the most recent unique SHA-1 values in each query chunk.",
                "Microsoft documents a maximum FileProfile enrichment limit of 1000 records per invocation.",
            ],
        }

    def collect(self, tables: Sequence[str], start: datetime, end: datetime) -> Dict[str, Any]:
        collected: Dict[str, Any] = {}
        for table in tables:
            logging.info("Collecting Defender Advanced Hunting table: %s", table)
            collected[table] = self.collect_table(table, start, end)

        if self.enable_file_profile and "DeviceFileEvents" in tables:
            logging.info("Resolving missing DeviceFileEvents SHA-256 values with FileProfile")
            collected["DeviceFileProfiles"] = self.collect_file_profiles(start, end)

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


def build_device_file_sha256_index(hunting: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Build a SHA-256 keyed summary from device file-related hunting events."""
    profile_by_sha1: Dict[str, Dict[str, Any]] = {}
    profile_data = hunting.get("DeviceFileProfiles", {})
    profile_rows = profile_data.get("results", []) if isinstance(profile_data, dict) else []
    if isinstance(profile_rows, list):
        for row in profile_rows:
            if not isinstance(row, dict):
                continue
            sha1 = normalize_hex_hash(row.get("SHA1"), 40)
            sha256 = normalize_hex_hash(row.get("SHA256"), 64)
            if sha1 and sha256:
                profile_by_sha1[sha1] = row

    index: Dict[str, Dict[str, Any]] = {}

    def add_unique(item: MutableMapping[str, Any], field: str, value: Any) -> None:
        if value in (None, ""):
            return
        values = item.setdefault(field, [])
        if value not in values:
            values.append(value)

    for table in DEVICE_FILE_EVENT_TABLES:
        table_data = hunting.get(table, {})
        rows = table_data.get("results", []) if isinstance(table_data, dict) else []
        if not isinstance(rows, list):
            continue

        for row in rows:
            if not isinstance(row, dict):
                continue

            sha1 = normalize_hex_hash(row.get("SHA1"), 40)
            sha256 = normalize_hex_hash(row.get("SHA256"), 64)
            sha256_source = f"{table}.SHA256"
            profile: Optional[Dict[str, Any]] = None

            if not sha256 and sha1:
                profile = profile_by_sha1.get(sha1)
                if profile:
                    sha256 = normalize_hex_hash(profile.get("SHA256"), 64)
                    if sha256:
                        sha256_source = "FileProfile(SHA1)"

            if not sha256:
                continue

            item = index.setdefault(
                sha256,
                {
                    "sha256": sha256,
                    "sha256Sources": [],
                    "sha1": [],
                    "md5": [],
                    "deviceIds": [],
                    "deviceNames": [],
                    "fileNames": [],
                    "folderPaths": [],
                    "actionTypes": [],
                    "tables": [],
                    "profileAvailability": [],
                    "firstSeen": None,
                    "lastSeen": None,
                    "eventCount": 0,
                },
            )

            item["eventCount"] += 1
            add_unique(item, "sha256Sources", sha256_source)
            add_unique(item, "sha1", sha1)
            add_unique(item, "md5", normalize_hex_hash(row.get("MD5"), 32))
            add_unique(item, "deviceIds", row.get("DeviceId"))
            add_unique(item, "deviceNames", row.get("DeviceName"))
            add_unique(item, "fileNames", row.get("FileName"))
            add_unique(item, "folderPaths", row.get("FolderPath"))
            add_unique(item, "actionTypes", row.get("ActionType"))
            add_unique(item, "tables", table)
            if profile:
                add_unique(item, "profileAvailability", profile.get("ProfileAvailability"))

            timestamp = row.get("Timestamp")
            if timestamp not in (None, ""):
                timestamp_text = str(timestamp)
                if item["firstSeen"] is None or timestamp_text < item["firstSeen"]:
                    item["firstSeen"] = timestamp_text
                if item["lastSeen"] is None or timestamp_text > item["lastSeen"]:
                    item["lastSeen"] = timestamp_text

    return sorted(index.values(), key=lambda item: item["sha256"])


def build_purview_sha256_index(activity_feed: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Index SHA-256 values found in raw Purview activity records."""
    index: Dict[str, Dict[str, Any]] = {}
    content_types = activity_feed.get("content_types", {})
    if not isinstance(content_types, Mapping):
        return []

    for content_type, content_data in content_types.items():
        events = content_data.get("events", []) if isinstance(content_data, Mapping) else []
        if not isinstance(events, list):
            continue

        for event in events:
            if not isinstance(event, Mapping):
                continue
            hashes = extract_sha256_values(event)
            for sha256 in hashes:
                item = index.setdefault(
                    sha256,
                    {
                        "sha256": sha256,
                        "contentTypes": [],
                        "eventIds": [],
                        "operations": [],
                        "workloads": [],
                        "deviceNames": [],
                        "objectIds": [],
                        "firstSeen": None,
                        "lastSeen": None,
                        "eventCount": 0,
                    },
                )
                item["eventCount"] += 1
                for field, value in (
                    ("contentTypes", content_type),
                    ("eventIds", event.get("Id") or event.get("id")),
                    ("operations", event.get("Operation") or event.get("operation")),
                    ("workloads", event.get("Workload") or event.get("workload")),
                    (
                        "deviceNames",
                        event.get("DeviceName")
                        or (
                            event.get("EndpointMetaData", {}).get("DeviceName")
                            if isinstance(event.get("EndpointMetaData"), Mapping)
                            else None
                        ),
                    ),
                    ("objectIds", event.get("ObjectId") or event.get("objectId")),
                ):
                    if value not in (None, "") and value not in item[field]:
                        item[field].append(value)

                timestamp = (
                    event.get("CreationTime")
                    or event.get("Timestamp")
                    or event.get("creationDateTime")
                )
                if timestamp not in (None, ""):
                    timestamp_text = str(timestamp)
                    if item["firstSeen"] is None or timestamp_text < item["firstSeen"]:
                        item["firstSeen"] = timestamp_text
                    if item["lastSeen"] is None or timestamp_text > item["lastSeen"]:
                        item["lastSeen"] = timestamp_text

    return sorted(index.values(), key=lambda item: item["sha256"])


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
    parser.add_argument(
        "--file-profile-limit",
        type=int,
        default=1000,
        help="Maximum SHA-1 values enriched with FileProfile per hunting chunk (1-1000).",
    )
    parser.add_argument(
        "--skip-file-profile",
        action="store_true",
        help="Do not use FileProfile(SHA1) to resolve missing DeviceFileEvents SHA-256 values.",
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
            "DeviceFileEvents.SHA256 is used directly when populated; missing values can be enriched from SHA1 with FileProfile().",
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
            hunting = AdvancedHuntingCollector(
                defender_client,
                args.hunting_chunk_hours,
                enable_file_profile=not args.skip_file_profile,
                file_profile_limit=args.file_profile_limit,
            ).collect(hunting_tables, start, end)
            result["xdr"]["advanced_hunting"] = hunting
            result["xdr"]["correlated_emails"] = build_correlated_email_index(hunting)
            result["xdr"]["correlated_email_count"] = len(result["xdr"]["correlated_emails"])
            result["xdr"]["device_file_sha256"] = build_device_file_sha256_index(hunting)
            result["xdr"]["device_file_sha256_count"] = len(result["xdr"]["device_file_sha256"])
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
            activity_feed = purview_collector.collect(
                purview_content_types, purview_start, end
            )
            result["purview"]["activity_feed"] = activity_feed
            result["purview"]["sha256_index"] = build_purview_sha256_index(activity_feed)
            result["purview"]["sha256_count"] = len(result["purview"]["sha256_index"])
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
