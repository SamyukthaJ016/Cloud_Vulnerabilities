# FieldGuide Integration

Synchronize audit data between GigaChad GRC and FieldGuide.

## Overview

The FieldGuide integration enables:
- Bi-directional sync of audit data
- Automatic request mapping
- Evidence sharing between platforms
- Real-time webhook updates

## Prerequisites

Before connecting:
- Active FieldGuide subscription
- FieldGuide Admin access
- OAuth application configured in FieldGuide
- Network access to FieldGuide API

## Connecting to FieldGuide

### 1. Navigate to Integration Settings

Go to **Settings → Integrations → FieldGuide**

### 2. Start OAuth Connection

Click **Connect to FieldGuide**

### 3. Authorize Access

1. Redirected to FieldGuide login
2. Enter FieldGuide credentials
3. Review requested permissions
4. Click **Authorize**
5. Redirected back to GigaChad GRC

### 4. Confirm Connection

Verify connection status shows:
- ✅ Connected
- Organization name
- Last sync time

## Sync Configuration

### Sync Direction

Choose how data flows:

| Option | Description |
|--------|-------------|
| **GigaChad → FieldGuide** | Push data to FieldGuide |
| **FieldGuide → GigaChad** | Pull data from FieldGuide |
| **Bi-directional** | Sync both directions |

### Data Mapping

Map GigaChad fields to FieldGuide:

| GigaChad Field | FieldGuide Field |
|----------------|------------------|
| Audit Name | Engagement Name |
| Request | Request |
| Finding | Issue |
| Evidence | Document |
| Status | Status |

### Sync Schedule

Configure sync frequency:
- **Real-time**: Webhook-based instant sync
- **Hourly**: Every hour
- **Daily**: Once per day
- **Manual**: On-demand only

## Syncing Audits

### Initial Sync

When first connecting:
1. Choose sync direction
2. Select audits to sync
3. Map existing data (optional)
4. Start initial sync
5. Review sync results

### Ongoing Sync

After initial sync:
- Changes sync automatically
- Conflicts handled per settings
- Errors logged and notified

### Manual Sync

Trigger sync on-demand:
1. Go to integration settings
2. Click **Sync Now**
3. Select what to sync
4. Confirm and start
5. View sync progress

## Request Synchronization

### Request Mapping

Map request statuses:

| GigaChad Status | FieldGuide Status |
|-----------------|-------------------|
| Open | Open |
| In Progress | In Progress |
| Submitted | Pending Review |
| Under Review | Under Review |
| Approved | Closed - Received |

### Evidence Sync

When syncing evidence:
- Files transferred between platforms
- Metadata preserved
- Links maintained
- Versions tracked

## Webhook Configuration

### Setting Up Webhooks

1. In FieldGuide, create webhook
2. Use GigaChad webhook URL:
   ```
   https://your-domain.com/api/fieldguide/webhooks
   ```
3. Select events to receive
4. Copy webhook secret
5. Enter secret in GigaChad

### Supported Events

| Event | Description |
|-------|-------------|
| `request.created` | New request in FieldGuide |
| `request.updated` | Request status changed |
| `document.uploaded` | Evidence uploaded |
| `issue.created` | New finding |
| `comment.created` | New comment |

## Conflict Resolution

### Conflict Types

When same item edited in both:
- Status conflicts
- Content conflicts
- Assignment conflicts

### Resolution Strategies

| Strategy | Behavior |
|----------|----------|
| **GigaChad Wins** | GigaChad version kept |
| **FieldGuide Wins** | FieldGuide version kept |
| **Latest Wins** | Most recent edit kept |
| **Manual** | Prompt user to choose |

### Conflict Log

View conflicts:
1. Go to integration settings
2. Click **Conflict Log**
3. Review unresolved conflicts
4. Resolve manually if needed

## Data Mapping

### Audit Mapping

| GigaChad | FieldGuide |
|----------|------------|
| `audit.name` | `engagement.name` |
| `audit.type` | `engagement.type` |
| `audit.startDate` | `engagement.start_date` |
| `audit.endDate` | `engagement.end_date` |
| `audit.framework` | `engagement.standard` |

### Finding Mapping

| GigaChad | FieldGuide |
|----------|------------|
| `finding.title` | `issue.title` |
| `finding.severity` | `issue.rating` |
| `finding.description` | `issue.description` |
| `finding.remediation` | `issue.recommendation` |

## Sync History

### Viewing History

Track all sync activities:
1. Go to integration settings
2. Click **Sync History**
3. View chronological log

### History Details

Each entry shows:
- Sync timestamp
- Direction
- Items synced
- Errors (if any)
- Duration

### Export History

Export for audit purposes:
- CSV format
- Date range filter
- Include/exclude errors

## Troubleshooting

### Connection Failed

1. Verify OAuth credentials
2. Check FieldGuide service status
3. Review network connectivity
4. Re-authorize if needed

### Sync Errors

1. Check error messages
2. Verify data mapping
3. Review field requirements
4. Check for conflicts

### Missing Data

1. Verify sync direction
2. Check item was saved
3. Review sync schedule
4. Trigger manual sync

### Webhook Failures

1. Verify webhook URL
2. Check webhook secret
3. Review FieldGuide logs
4. Test with sample event

## Security Considerations

### Data Protection

- OAuth tokens encrypted
- Data transmitted via HTTPS
- Access logged
- Tokens rotatable

### Permissions

- Separate sync service account
- Minimum required permissions
- Regular access review
- Audit trail maintained

## Disconnecting

### Temporary Disconnect

Pause integration:
1. Go to integration settings
2. Toggle **Enabled** off
3. Sync paused, data retained

### Permanent Disconnect

Remove integration:
1. Go to integration settings
2. Click **Disconnect**
3. Confirm disconnection
4. Local data retained
5. FieldGuide data unaffected

## Related Topics

- [Audit Management](audits.md)
- [Audit Requests](requests.md)
- [Auditor Portal](auditor-portal.md)

