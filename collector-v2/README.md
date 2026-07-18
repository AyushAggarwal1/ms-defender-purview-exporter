# Microsoft Defender XDR + Microsoft Purview JSON Exporter

This collector exports the broadest supported security and compliance data set available through the APIs used by Microsoft Defender XDR and Microsoft Purview.

## Sources collected by default

### Microsoft Defender XDR

1. Microsoft Graph Security incidents
   - `GET /security/incidents`
2. Microsoft Graph Security alerts
   - `GET /security/alerts_v2`
3. Every table currently documented in the Microsoft Defender XDR Advanced Hunting schema
   - 64 tables, including endpoint, email, identity, cloud apps, cloud infrastructure, exposure management, AI agents, Teams messages, vulnerability management, and Purview-backed data security tables
4. Correlated email metadata indexed by `NetworkMessageId`

### Microsoft Purview

1. Microsoft Graph Purview Audit Search API
   - Creates asynchronous searches through `/security/auditLog/queries`
   - Retrieves every audit record type returned by the tenant, permissions, licensing, and retention configuration
2. Office 365 Management Activity API
   - `Audit.AzureActiveDirectory`
   - `Audit.Exchange`
   - `Audit.SharePoint`
   - `Audit.General`
   - `DLP.All`
3. Purview-backed Advanced Hunting tables
   - `DataSecurityEvents`
   - `DataSecurityBehaviors`

Microsoft exposes exactly five Management Activity content types. `Audit.General` includes workloads that are not represented by the Entra, Exchange, or SharePoint feeds.

## Important limitation

There is no universal API that bulk-exports every screen or object displayed in Purview Data Explorer or Content Explorer. The collector uses all relevant supported programmatic paths available for this use case:

- Purview unified audit records
- Management Activity audit and DLP events
- `DataSecurityEvents`
- `DataSecurityBehaviors`
- XDR alerts and incidents, including integrated Purview DLP and Insider Risk alerts when enabled

The collector does not download document contents, mailbox bodies, or unmasked sensitive values.

## 1. Application permissions

Create or open an app registration in Microsoft Entra ID, add the following **Application permissions**, and grant tenant-wide administrator consent.

### Microsoft Graph

Required for incidents and alerts:

- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`

Recommended for the current Advanced Hunting API:

- `ThreatHunting.Read.All`

Required for the Purview Audit Search API:

- `AuditLogsQuery.Read.All`

The collector uses Microsoft Graph `runHuntingQuery` when `ThreatHunting.Read.All` is available.

### Microsoft Threat Protection

Legacy fallback permission:

- `AdvancedHunting.Read.All`

The collector can use this permission when `ThreatHunting.Read.All` has not yet been added. Microsoft is retiring the legacy Advanced Hunting endpoint, so migrate to `ThreatHunting.Read.All`.

### Office 365 Management APIs

These must be **Application**, not Delegated, permissions:

- `ActivityFeed.Read`
- `ActivityFeed.ReadDlp`

## 2. Tenant prerequisites

- Relevant Microsoft Defender products must be deployed and licensed.
- Defender for Office 365 is required for email and Teams message hunting tables.
- Defender for Endpoint is required for device and vulnerability-management tables.
- Defender for Identity is required for on-premises identity tables.
- Defender for Cloud Apps is required for cloud app and behavior tables.
- Defender for Cloud and Security Exposure Management are required for their related tables.
- Purview unified auditing must be enabled.
- Purview Activity Feed subscriptions must be enabled.
- Purview Insider Risk and Data Security integration with Defender must be enabled for all Purview-backed hunting tables to return data.
- Defender unified RBAC must allow the app or assigned workload access to the requested raw data.

A table can return no rows or an availability error when its corresponding product, preview, integration, permission, or license is not enabled. The collector records the error and continues with the remaining tables.

## 3. Install

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Populate `.env`:

```dotenv
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
PURVIEW_PUBLISHER_IDENTIFIER=your-tenant-id
```

Certificate authentication is also supported through the variables documented in `.env.example`.

## 4. Enable every Purview Management Activity subscription

Run each command once. New subscriptions can take time before the first content blobs become available.

```bash
python collector.py --start-subscription Audit.AzureActiveDirectory
python collector.py --start-subscription Audit.Exchange
python collector.py --start-subscription Audit.SharePoint
python collector.py --start-subscription Audit.General
python collector.py --start-subscription DLP.All
```

## 5. Export everything

The default command now requests all 64 XDR hunting tables, Graph incidents and alerts, Purview Audit Search records, and all five Management Activity feeds:

```bash
python collector.py --days 1 --pretty --output complete-export.json
```

For a fixed UTC range:

```bash
python collector.py \
  --start 2026-07-16T00:00:00Z \
  --end   2026-07-17T00:00:00Z \
  --pretty \
  --output complete-export.json
```

## 6. Advanced Hunting API selection

Default behavior:

```bash
--hunting-api auto
```

`auto` tries the current Microsoft Graph endpoint first and falls back to the legacy Defender endpoint.

Force Microsoft Graph:

```bash
python collector.py --days 1 --hunting-api graph --pretty --output graph-hunting.json
```

Force the legacy endpoint:

```bash
python collector.py --days 1 --hunting-api legacy --pretty --output legacy-hunting.json
```

## 7. High-volume controls

Advanced Hunting limits each query by row count and result size. The collector:

- Probes each table's schema.
- Uses time slicing when a `Timestamp` column exists.
- Recursively splits a time slice when it reaches the configured row ceiling.
- Uses a snapshot/entity query for tables without `Timestamp`.
- Marks `possible_truncation` when it cannot split further or a snapshot hits the row ceiling.

Useful options:

```bash
python collector.py \
  --days 1 \
  --hunting-chunk-hours 1 \
  --hunting-min-chunk-minutes 1 \
  --hunting-max-rows 100000 \
  --pretty \
  --output high-volume-export.json
```

Snapshot/entity tables cannot be generically paginated beyond the Advanced Hunting API's row and response-size ceilings because they do not expose a universal stable cursor. The JSON explicitly identifies possible truncation.

## 8. Purview Audit Search controls

The Audit Search API is asynchronous. The collector creates a search, waits for completion, and follows Graph pagination for all returned records.

```bash
python collector.py \
  --days 30 \
  --purview-audit-chunk-days 7 \
  --purview-audit-poll-seconds 5 \
  --purview-audit-timeout-seconds 900 \
  --pretty \
  --output 30-day-export.json
```

Audit availability depends on your tenant's Purview Audit licensing and retention policies.

## 9. Select or skip sources

Only selected hunting tables:

```bash
python collector.py --days 1 \
  --hunting-table EmailEvents \
  --hunting-table EmailAttachmentInfo \
  --hunting-table DataSecurityEvents \
  --pretty --output selected-tables.json
```

Only Purview:

```bash
python collector.py --days 1 \
  --skip-graph-security \
  --skip-hunting \
  --pretty --output purview-only.json
```

Skip the asynchronous Purview Audit Search API but keep the activity feed:

```bash
python collector.py --days 1 \
  --skip-purview-audit-search \
  --pretty --output activity-feed-only.json
```

Skip the seven-day activity feed but keep Purview Audit Search:

```bash
python collector.py --days 30 \
  --skip-purview-activity-feed \
  --pretty --output audit-search-only.json
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
xdr.advanced_hunting_metadata
xdr.correlated_emails[]

purview.audit_search.windows[]
purview.audit_search.records[]
purview.audit_search.errors[]

purview.activity_feed.subscriptions[]
purview.activity_feed.content_types.<ContentType>.events[]
purview.activity_feed.dlp_sensitive_types[]

errors[]
```

## All Advanced Hunting tables requested by default

```text
AADSignInEventsBeta
AADSpnSignInEventsBeta
AgentsInfo
AIAgentsInfo
AlertEvidence
AlertInfo
BehaviorEntities
BehaviorInfo
CampaignInfo
CloudAppEvents
CloudAuditEvents
CloudDnsEvents
CloudPolicyEnforcementEvents
CloudProcessEvents
CloudStorageAggregatedEvents
DataSecurityBehaviors
DataSecurityEvents
DeviceBaselineComplianceAssessment
DeviceBaselineComplianceAssessmentKB
DeviceBaselineComplianceProfiles
DeviceEvents
DeviceFileCertificateInfo
DeviceFileEvents
DeviceImageLoadEvents
DeviceInfo
DeviceLogonEvents
DeviceNetworkEvents
DeviceNetworkInfo
DeviceProcessEvents
DeviceRegistryEvents
DeviceTvmBrowserExtensions
DeviceTvmBrowserExtensionsKB
DeviceTvmCertificateInfo
DeviceTvmHardwareFirmware
DeviceTvmInfoGathering
DeviceTvmInfoGatheringKB
DeviceTvmSecureConfigurationAssessment
DeviceTvmSecureConfigurationAssessmentKB
DeviceTvmSoftwareEvidenceBeta
DeviceTvmSoftwareInventory
DeviceTvmSoftwareVulnerabilities
DeviceTvmSoftwareVulnerabilitiesKB
DisruptionAndResponseEvents
EmailAttachmentInfo
EmailEvents
EmailPostDeliveryEvents
EmailUrlInfo
EntraIdSignInEvents
EntraIdSpnSignInEvents
ExposureGraphEdges
ExposureGraphNodes
FileMaliciousContentInfo
GraphApiAuditEvents
IdentityAccountInfo
IdentityDirectoryEvents
IdentityEvents
IdentityInfo
IdentityLogonEvents
IdentityQueryEvents
MessageEvents
MessagePostDeliveryEvents
MessageUrlInfo
OAuthAppInfo
UrlClickEvents
```

## Security notes

Do not commit `.env` or exported JSON. Exports can contain identities, email subjects, file names, URLs, IP addresses, device data, audit records, DLP details, and investigation metadata. Encrypt stored exports and apply appropriate access, retention, and deletion controls.
