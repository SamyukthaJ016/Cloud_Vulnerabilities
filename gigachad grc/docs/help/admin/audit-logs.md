# Audit Logs

The Audit Log provides a comprehensive record of all actions taken within the platform, supporting compliance requirements and security monitoring.

## Overview

Audit logs capture:
- Who performed an action
- What action was taken
- When it occurred
- What changed (before/after)
- Additional context (IP, browser)

## Accessing Audit Logs

Navigate to **Settings → Audit Log** to view the audit trail.

## Log Entry Details

### Entry Fields

| Field | Description |
|-------|-------------|
| **Timestamp** | When the action occurred (UTC) |
| **User** | Who performed the action |
| **Action** | What was done |
| **Entity Type** | Type of item affected |
| **Entity** | Specific item affected |
| **Description** | Human-readable summary |
| **Changes** | Before/after values (if applicable) |
| **IP Address** | Source IP address |
| **User Agent** | Browser/client information |

### Action Types
- **Create**: New item created
- **Update**: Item modified
- **Delete**: Item removed
- **Login**: User login event
- **Logout**: User logout event
- **Export**: Data exported
- **Import**: Data imported
- **Config Change**: Settings modified

## Searching and Filtering

### Quick Search
Type in the search bar to find logs by:
- User name/email
- Entity name
- Action description

### Advanced Filters

| Filter | Options |
|--------|---------|
| **Date Range** | From/to dates |
| **User** | Specific user |
| **Action Type** | Create, Update, Delete, etc. |
| **Entity Type** | Controls, Risks, Users, etc. |
| **Entity ID** | Specific item |

### Saved Filters
1. Configure your filters
2. Click **Save Filter**
3. Name the filter
4. Reuse later

## Viewing Log Details

### Summary View
The log list shows:
- Timestamp
- User
- Action summary
- Entity type and name

### Detailed View
Click any entry to see:
- Full action details
- Complete change history
- IP and browser info
- Related entries

### Change Comparison
For update actions:
- **Before**: Previous values
- **After**: New values
- Side-by-side comparison

## Exporting Audit Logs

### Manual Export
1. Apply desired filters
2. Click **Export**
3. Choose format:
   - CSV (spreadsheet)
   - JSON (structured data)
   - PDF (formatted report)
4. Download file

### Scheduled Export
1. Go to **Tools → Scheduled Reports**
2. Create new report
3. Select **Audit Log Export**
4. Configure schedule
5. Set delivery (email or storage)

## Log Retention

### Retention Period
Configure in **Settings → Organization**:
- 90 days
- 1 year
- 2 years
- Custom period

### Compliance Requirements
Common requirements:
- SOC 2: 1 year minimum
- ISO 27001: Based on policy
- PCI DSS: 1 year online, 1 year archive
- HIPAA: 6 years

### Archive Export
Before logs age out:
1. Export historical logs
2. Store in secure archive
3. Maintain chain of custody

## Security Monitoring

### Suspicious Activity Indicators
Watch for:
- Multiple failed logins
- Unusual access times
- Bulk deletions
- Permission changes
- Settings modifications

### Alerting
Configure alerts for critical events:
1. Go to **Settings → Notifications**
2. Enable **Audit Alerts**
3. Select events to monitor
4. Configure recipients

## Common Use Cases

### Access Review
Review who accessed what:
1. Filter by user
2. Set date range
3. Review all actions
4. Document findings

### Incident Investigation
Investigate security incidents:
1. Identify relevant time window
2. Filter by entity or user
3. Trace sequence of events
4. Export for evidence

### Compliance Audit
Demonstrate compliance:
1. Export logs for audit period
2. Filter by relevant controls
3. Show access controls working
4. Provide to auditors

### Change Tracking
Track specific item changes:
1. Filter by entity type and ID
2. See complete history
3. Review each modification
4. Identify who made changes

## Integration

### SIEM Integration
Export logs to SIEM systems:
- Splunk
- QRadar
- Elastic SIEM
- Azure Sentinel

Configure in **Settings → Integrations**.

### API Access
Retrieve logs programmatically:
```
GET /api/audit-logs?from=2024-01-01&to=2024-01-31
```

See [API Reference](/docs/API.md) for details.

## Best Practices

### Regular Review
- Daily review of critical events
- Weekly summary review
- Monthly trend analysis

### Alert Configuration
- Alert on admin actions
- Alert on bulk operations
- Alert on failed logins

### Documentation
- Document review processes
- Maintain investigation records
- Archive for compliance

### Access Control
- Limit who can view logs
- Log access to logs themselves
- Protect exported files

## Troubleshooting

### Missing Logs
1. Check date range filter
2. Verify event type included
3. Check retention period
4. Contact support if unexpected

### Export Issues
1. Reduce date range
2. Apply filters to limit size
3. Try different format
4. Check storage space

## Related Topics

- [Organization Settings](organization.md)
- [User Management](users.md)
- [Permission Groups](permissions.md)

