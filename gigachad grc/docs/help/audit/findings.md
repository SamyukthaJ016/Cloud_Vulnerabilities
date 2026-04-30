# Audit Findings

Audit findings document issues discovered during audits and track their remediation. This guide covers managing findings from identification through resolution.

## Overview

The Findings module helps you:
- Document audit observations
- Classify severity and impact
- Assign remediation owners
- Track resolution progress
- Report on findings trends

## Finding Types

| Type | Description |
|------|-------------|
| **Deficiency** | Control not operating effectively |
| **Gap** | Missing control or requirement |
| **Observation** | Area for improvement (not a deficiency) |
| **Recommendation** | Suggested enhancement |

## Finding Severity

| Level | Description | Response Time |
|-------|-------------|---------------|
| **Critical** | Major risk, immediate action | 30 days |
| **High** | Significant issue | 60 days |
| **Medium** | Moderate concern | 90 days |
| **Low** | Minor issue | 180 days |
| **Informational** | Awareness only | No deadline |

## Viewing Findings

Navigate to **Audit → Findings** to see all findings.

### Filters
- **Audit**: From specific audit
- **Severity**: Critical, High, etc.
- **Status**: Open, In Progress, Closed
- **Assigned To**: By remediation owner
- **Framework**: Related framework

### Sorting
Sort by:
- Severity (default)
- Due date
- Created date
- Status

## Creating Findings

### From Audit
1. Open an audit
2. Go to **Findings** tab
3. Click **Add Finding**
4. Fill in details:
   - **Title**: Brief description
   - **Type**: Deficiency, Gap, etc.
   - **Severity**: Risk level
   - **Description**: Full details
   - **Impact**: Business impact
   - **Recommendation**: Suggested fix
   - **Related Control**: Affected control
5. Assign remediation:
   - **Owner**: Who will fix
   - **Due Date**: Based on severity
6. Click **Create**

### Standalone Finding
1. Go to **Audit → Findings**
2. Click **Create Finding**
3. Select or create audit association
4. Fill in details as above

## Finding Detail Page

Click any finding to see:

### Overview
- Finding summary
- Severity and status
- Assignment details
- Timeline

### Evidence
- Evidence supporting the finding
- Auditor documentation

### Remediation
- Remediation plan
- Progress updates
- Action items

### Activity
- Status changes
- Comments
- Attachments

## Remediation Workflow

```
┌────────┐   ┌─────────────┐   ┌────────────┐   ┌──────────┐
│  Open  │──▶│ In Progress │──▶│ Remediated │──▶│ Verified │
└────────┘   └─────────────┘   └────────────┘   └──────────┘
                                                     │
                                                     ▼
                                                ┌─────────┐
                                                │ Closed  │
                                                └─────────┘
```

### Status Definitions

| Status | Description |
|--------|-------------|
| **Open** | Finding identified, not yet addressed |
| **In Progress** | Remediation underway |
| **Remediated** | Fix implemented, awaiting verification |
| **Verified** | Fix confirmed effective |
| **Closed** | Finding fully resolved |
| **Accepted** | Risk accepted (with approval) |

## Remediation Planning

### Create Remediation Plan
1. Open finding
2. Go to **Remediation** tab
3. Click **Create Plan**
4. Document:
   - Remediation approach
   - Required resources
   - Action items with owners
   - Target completion dates

### Track Progress
1. Update action items as completed
2. Add progress notes
3. Upload supporting evidence
4. Adjust timeline if needed

## Verification

### Request Verification
After remediation:
1. Click **Submit for Verification**
2. Provide evidence of fix
3. Add notes

### Verify Finding
As verifier:
1. Review remediation evidence
2. Test the fix if applicable
3. Choose action:
   - **Verified**: Fix is effective
   - **Reopen**: Fix is inadequate

## Risk Acceptance

For findings that won't be remediated:

1. Click **Request Acceptance**
2. Document:
   - Justification for acceptance
   - Compensating controls
   - Acceptance period
3. Route for approval
4. Approved: Finding marked Accepted
5. Set review date for re-evaluation

## Reporting

### Findings Dashboard
Shows:
- Open findings by severity
- Findings by audit
- Remediation progress
- Trends over time

### Findings Report
Generate detailed report:
1. Go to **Audit → Findings**
2. Click **Generate Report**
3. Select parameters
4. Download PDF

### Aging Report
Track overdue findings:
- Days past due
- Escalation status
- Owner accountability

## Notifications

Automatic alerts for:
- New finding assigned
- Due date approaching
- Status changes
- Verification requests

## Best Practices

### Documentation
- Clear, specific descriptions
- Include evidence references
- Document business impact
- Provide actionable recommendations

### Remediation
- Set realistic timelines
- Break into manageable tasks
- Regular progress updates
- Escalate blockers early

### Follow-Up
- Verify fixes thoroughly
- Re-test after remediation
- Document lessons learned
- Update controls/processes

## Related Topics

- [Audit Management](audits.md)
- [Audit Requests](requests.md)
- [Controls Management](../compliance/controls.md)

