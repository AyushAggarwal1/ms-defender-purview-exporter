# Microsoft Defender XDR + Microsoft Purview JSON Exporter

This Python collector exports Microsoft Defender XDR and Microsoft Purview activity data to a JSON file.

## Collected sources

### Microsoft Graph Security

- `GET /security/incidents`
- `GET /security/alerts_v2`
- Follows `@odata.nextLink` until all pages are retrieved
- Uses `$top=50` for incidents because Microsoft Graph rejects larger incident page sizes

### Microsoft Defender XDR Advanced Hunting

The collector requests all 64 tables currently listed in the Microsoft Defender XDR Advanced Hunting schema.

It automatically:

- probes each table schema;
- time-slices tables that contain `Timestamp`;
- recursively splits a time slice when a query reaches 100,000 rows;
- queries tables without `Timestamp` as current snapshot/entity tables;
- records unavailable or unlicensed tables as errors without stopping the full export.

### Microsoft Purview Management Activity API

- `Audit.AzureActiveDirectory`
- `Audit.Exchange`
- `Audit.SharePoint`
- `Audit.General`
- `DLP.All`

These are the content types Microsoft exposes through the Office 365 Management Activity API. `Audit.General` contains records for additional Microsoft 365 workloads.

## Required application permissions

Add these as **Application permissions** and grant tenant-wide admin consent.

### Microsoft Graph

- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`

### Microsoft Threat Protection

- `AdvancedHunting.Read.All`

### Office 365 Management APIs

- `ActivityFeed.Read`
- `ActivityFeed.ReadDlp`

Delegated permissions do not work with this collector's client-secret or certificate authentication flow.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Populate `.env`:

```dotenv
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
PURVIEW_PUBLISHER_IDENTIFIER=your-tenant-id
```

Certificate authentication is also supported through the variables in `.env.example`.

## Enable Purview subscriptions

Run each command once:

```bash
python collector.py --start-subscription Audit.AzureActiveDirectory
python collector.py --start-subscription Audit.Exchange
python collector.py --start-subscription Audit.SharePoint
python collector.py --start-subscription Audit.General
python collector.py --start-subscription DLP.All
```

New subscriptions may not return data immediately.

## Export all configured sources

```bash
python collector.py --days 1 --pretty --output export.json
```

For a fixed UTC range:

```bash
python collector.py \
  --start 2026-07-17T00:00:00Z \
  --end 2026-07-18T00:00:00Z \
  --pretty \
  --output export.json
```

## Useful options

Collect selected hunting tables only:

```bash
python collector.py --days 1 \
  --hunting-table EmailEvents \
  --hunting-table EmailAttachmentInfo \
  --hunting-table DataSecurityEvents \
  --pretty --output selected.json
```

Skip individual source groups:

```bash
--skip-graph-security
--skip-hunting
--skip-purview
```

Change the initial hunting time-slice size:

```bash
--hunting-chunk-hours 1
```

## Output structure

```text
xdr.graph_security.incidents[]
xdr.graph_security.alerts[]

xdr.advanced_hunting.<Table>.results[]
xdr.advanced_hunting.<Table>.schema[]
xdr.advanced_hunting.<Table>.collection_mode
xdr.advanced_hunting.<Table>.possible_truncation
xdr.advanced_hunting.<Table>.errors[]

xdr.correlated_emails[]

purview.activity_feed.subscriptions[]
purview.activity_feed.content_types.<ContentType>.events[]
purview.activity_feed.dlp_sensitive_types[]

errors[]
```

## Important limitations

- Defender Advanced Hunting normally exposes up to 30 days of raw Defender data.
- A hunting query can return at most 100,000 rows and is also subject to response-size and CPU quotas.
- The collector recursively splits timestamped queries, but a snapshot table that itself exceeds 100,000 rows cannot be generically paginated through Advanced Hunting. Such output is marked with `possible_truncation: true`.
- The Purview Management Activity API can list only content made available during the preceding seven days and requires query windows of 24 hours or less; the collector handles those windows automatically.
- Purview Data Explorer and Content Explorer do not expose one universal API for exporting every item shown in those portals.
- A table may return no data or an error when its related Defender/Purview product, integration, preview, license, or RBAC permission is unavailable.

## Security

Do not commit `.env` or the generated JSON. The export can contain identities, email subjects, file names, URLs, IP addresses, device data, audit records, and DLP metadata.
