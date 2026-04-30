# Evidence Retention Policies

Automate evidence lifecycle management with retention policies.

## Overview

Evidence retention policies help you:
- Comply with data retention requirements
- Automatically clean up expired evidence
- Maintain required evidence for audits
- Reduce storage costs

## Default Retention

Without custom policies, evidence follows organization defaults:

| Evidence Type | Default Retention |
|---------------|-------------------|
| Audit evidence | 7 years |
| Policy documents | Indefinite |
| Screenshots | 1 year |
| Logs | 90 days |
| Certificates | Duration + 1 year |

## Creating Retention Policies

### 1. Navigate to Settings

Go to **Settings → Evidence → Retention Policies**

### 2. Click Create Policy

Provide policy details:

| Field | Description |
|-------|-------------|
| **Name** | Policy identifier |
| **Description** | Purpose and scope |
| **Evidence Types** | Which evidence types apply |
| **Retention Period** | How long to keep |
| **Action** | What happens when expired |

### 3. Set Conditions

Define when policy applies:

```
If evidence matches ALL:
- Type: Screenshot
- Source: Automated Collection
- Age: > 365 days

Then: Archive
```

### 4. Configure Actions

What happens to expired evidence:

| Action | Description |
|--------|-------------|
| **Archive** | Move to long-term storage |
| **Delete** | Permanently remove |
| **Notify** | Alert owner before action |
| **Review** | Require manual approval |

### 5. Enable Policy

Toggle policy active and save.

## Policy Types

### Time-Based Retention

Keep evidence for specific duration:
- 90 days from collection
- 1 year from upload
- 7 years from control implementation

### Event-Based Retention

Keep evidence until event:
- Until audit completion
- Until control decommission
- Until policy update

### Legal Hold

Preserve evidence indefinitely:
- Litigation hold
- Regulatory investigation
- Special preservation

## Retention Schedule

### Automatic Processing

The system processes retention daily:
1. Identifies expired evidence
2. Applies configured actions
3. Logs all activities
4. Sends notifications

### Processing Time

Configure when processing runs:
- Default: 2:00 AM (organization timezone)
- Configurable in settings
- Avoids peak usage times

## Notifications

### Before Expiration

Warn before evidence expires:
- 30 days before (configurable)
- Email to evidence owner
- In-app notification
- Option to extend

### On Expiration

Notify when action taken:
- Confirmation to owner
- Audit log entry
- Admin notification (optional)

## Compliance Considerations

### Framework Requirements

| Framework | Typical Retention |
|-----------|-------------------|
| SOC 2 | 1 year minimum |
| ISO 27001 | 3 years |
| HIPAA | 6 years |
| PCI DSS | 1 year |
| GDPR | As long as necessary |

### Legal Requirements

Consider:
- Industry regulations
- Contract requirements
- Local laws
- Litigation holds

### Audit Trail

All retention activities logged:
- What was processed
- When action taken
- Who configured policy
- Original evidence metadata

## Managing Policies

### Policy Priority

When multiple policies match:
1. Legal holds take precedence
2. Longest retention wins
3. Manual holds override auto

### Editing Policies

Changes affect:
- Future processing only
- Already expired items unaffected
- Requires admin permission

### Disabling Policies

When disabled:
- No new processing
- Existing evidence unaffected
- Re-enable resumes processing

## Evidence States

### Normal

Standard evidence lifecycle:
1. Active (in use)
2. Approaching expiration
3. Expired
4. Archived/Deleted

### On Hold

Evidence preserved:
- Legal hold
- Audit hold
- Manual preservation

### Archived

Evidence in cold storage:
- Reduced accessibility
- Lower storage cost
- Retrievable when needed

## Best Practices

### Policy Design

- Start with compliance requirements
- Consider business needs
- Document rationale
- Review regularly

### Exception Handling

- Plan for legal holds
- Allow manual overrides
- Log all exceptions
- Review periodically

### Storage Management

- Archive before delete
- Monitor storage usage
- Plan for growth
- Budget appropriately

## Troubleshooting

### Evidence Not Expiring

- Check policy is enabled
- Verify conditions match
- Review processing logs
- Check for holds

### Unexpected Deletion

- Review audit logs
- Check policy conditions
- Verify retention period
- Look for overlapping policies

### Notifications Not Sent

- Check notification settings
- Verify email addresses
- Review notification logs
- Test with manual trigger

## Related Topics

- [Evidence Collection](../compliance/evidence.md)
- [Evidence Collectors](evidence-collectors.md)
- [Organization Settings](../admin/organization.md)

