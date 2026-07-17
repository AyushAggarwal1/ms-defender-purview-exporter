# Microsoft 365 XDR + Purview JSON Exporter

This Python collector exports:

- Microsoft Defender XDR incidents and alerts through Microsoft Graph.
- Defender Advanced Hunting alert and email metadata, including subject, sender, recipient, attachment names/hashes, URLs, click events, and post-delivery actions where available.
- Microsoft Purview unified audit and DLP activity through the Office 365 Management Activity API.
- A correlated email index keyed by `NetworkMessageId`.

It writes one JSON file and preserves every raw field returned by each API.

## Important scope limitation

There is no single API that exports every Purview Data Explorer or Content Explorer screen. Activity Explorer is primarily based on Microsoft 365 unified audit logs. This project therefore pulls the supported audit/DLP activity feed. It does not download document bodies or expose unmasked sensitive values.

## 1. Create an Entra app registration

In **Microsoft Entra admin center > App registrations > New registration**, create an app. Under **Certificates & secrets**, create a client secret for testing or upload a certificate for app-only authentication. The sample supports either a secret or a PEM private key plus certificate thumbprint.

Add these **Application permissions**, then select **Grant admin consent**:

### Microsoft Graph

- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`

### Microsoft Threat Protection

Find **APIs my organization uses > Microsoft Threat Protection** and add:

- `AdvancedHunting.Read.All`

Depending on your tenant's Defender unified RBAC configuration, the app also needs access to email and collaboration raw data.

### Office 365 Management APIs

Find **Office 365 Management APIs** and add:

- `ActivityFeed.Read`
- `ActivityFeed.ReadDlp` when you need the DLP sensitive-data details Microsoft allows the feed to return.

The app will request three resource-specific tokens:

- `https://graph.microsoft.com/.default`
- `https://api.security.microsoft.com/.default`
- `https://manage.office.com/.default`

## 2. Prerequisites in the tenant

- Microsoft Defender XDR and the relevant Defender products must be deployed.
- Defender for Office 365 is required for `EmailEvents`, `EmailAttachmentInfo`, and related email tables.
- Microsoft Purview unified auditing must be enabled.
- Purview activity-feed subscriptions must be enabled before content is available.
- New Purview subscriptions can take up to 12 hours before the first blobs appear.

## 3. Install

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with the tenant ID and client ID, then configure either the client-secret value or the certificate path and thumbprint.

## 4. Enable Purview activity subscriptions

Run one command for each desired content type. Microsoft recommends allowing 15 minutes between subscription-start requests.

```bash
python collector.py --start-subscription Audit.AzureActiveDirectory
python collector.py --start-subscription Audit.Exchange
python collector.py --start-subscription Audit.SharePoint
python collector.py --start-subscription Audit.General
python collector.py --start-subscription DLP.All
```

Starting an already-enabled subscription is harmless only when the API accepts the request; use the error output to confirm tenant behavior.

## 5. Export the last 24 hours

```bash
python collector.py --days 1 --pretty --output export.json
```

Export a fixed UTC window:

```bash
python collector.py \
  --start 2026-07-16T00:00:00Z \
  --end   2026-07-17T00:00:00Z \
  --pretty \
  --output export.json
```

## 6. Useful variations

Only XDR data:

```bash
python collector.py --days 1 --skip-purview --pretty --output xdr.json
```

Only Purview activity data:

```bash
python collector.py --days 1 --skip-graph-security --skip-hunting --pretty --output purview.json
```

Select specific hunting tables:

```bash
python collector.py --days 1 \
  --hunting-table EmailEvents \
  --hunting-table EmailAttachmentInfo \
  --hunting-table EmailUrlInfo \
  --pretty --output email-metadata.json
```

Select specific Purview content types:

```bash
python collector.py --days 1 \
  --purview-content-type DLP.All \
  --purview-content-type Audit.Exchange \
  --pretty --output purview-dlp-exchange.json
```

## Output structure

```text
xdr.graph_security.incidents[]
xdr.graph_security.alerts[]
xdr.advanced_hunting.<Table>.results[]
xdr.correlated_emails[]
purview.activity_feed.subscriptions[]
purview.activity_feed.content_types.<ContentType>.events[]
purview.activity_feed.dlp_sensitive_types[]
errors[]
```

Each `xdr.correlated_emails[]` entry can include:

- `networkMessageId`
- `subjects`
- `senders`
- `recipients`
- `attachmentNames`
- `urlsFound`
- Full source rows from email, attachment, URL-click, and post-delivery tables

## Operational limits and troubleshooting

- Graph collection follows `@odata.nextLink` pagination.
- Purview collection follows the `NextPageUri` response header.
- Purview content-list windows are split into 24-hour blocks and capped to the last seven days.
- Advanced Hunting is split into configurable time chunks; default is six hours.
- `401/429/5xx` responses are retried with token refresh/backoff.
- A table can return no rows because the related Defender product is not deployed or the app lacks access.
- Management Activity API records can contain duplicates; the exporter de-duplicates by record ID when available.
- An alert can legitimately omit subject or file evidence. The correlated hunting output is the enrichment path for those fields.

## Security notes

Do not commit `.env` or exported JSON. Exports can contain user identities, message subjects, file names, URLs, IP addresses, and compliance metadata. Store them encrypted and apply retention/access controls.
