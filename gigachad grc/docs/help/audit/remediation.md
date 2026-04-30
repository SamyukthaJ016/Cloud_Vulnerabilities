# Remediation Plans (POA&M)

Remediation plans track the resolution of audit findings through structured Plans of Action and Milestones (POA&M). GigaChad GRC provides comprehensive tracking from finding to closure.

## Overview

POA&M management includes:
- **Milestone Tracking**: Break plans into achievable milestones
- **Resource Assignment**: Track who's responsible and effort required
- **Progress Monitoring**: Real-time status updates
- **Reporting**: Export for management and auditor reporting

## Accessing Remediation Plans

1. Navigate to **Audit → Findings** and click on a finding
2. From the finding detail, click **Create Remediation Plan**
3. Or access all plans from the Analytics → POA&M section

## Plan Structure

### Header Information
- **Plan Number**: Unique identifier (e.g., POA-2024-001)
- **Finding**: Link to the related audit finding
- **Description**: Overall remediation approach
- **Status**: Current state (Open, In Progress, Completed)

### Schedule
- **Scheduled Start**: When work should begin
- **Scheduled End**: Target completion date
- **Actual Start**: When work actually began
- **Actual End**: When plan was completed

### Resources
- **Owner**: Primary responsible person
- **Team**: Supporting team members
- **Estimated Hours**: Total effort estimate
- **Budget**: Optional cost tracking

### Milestones
- Individual steps to complete the plan
- Each has due dates and status
- Progress percentage based on milestone completion

## Creating a Remediation Plan

1. From a finding, click **Create Remediation Plan**
2. Fill in plan details:

### Basic Information
```
Plan Number: POA-2024-001 (auto-generated)
Description: Implement quarterly user access review process
Status: Open
```

### Schedule
```
Scheduled Start: January 1, 2025
Scheduled End: March 31, 2025
```

### Resources
```
Owner: Security Manager
Team: IT Operations, HR
Estimated Hours: 120
```

3. Add milestones:

### Milestone 1
```
Title: Define access review process
Due Date: January 31, 2025
Description: Document formal UAR procedure
Assigned To: Security Analyst
```

### Milestone 2
```
Title: Select and configure tooling
Due Date: February 15, 2025
Description: Evaluate and implement access review tool
Assigned To: IT Operations
```

### Milestone 3
```
Title: Conduct first quarterly review
Due Date: March 15, 2025
Description: Execute first full UAR cycle
Assigned To: Security Manager
```

4. Click **Create Plan**

## Tracking Progress

### Milestone Status Updates
1. Open the remediation plan
2. Click on a milestone
3. Update status:
   - **Pending**: Not started
   - **In Progress**: Work underway
   - **Completed**: Finished
   - **Blocked**: Waiting on dependency
4. Add notes about progress
5. Save changes

### Progress Percentage
- Automatically calculated from milestone completion
- Example: 2 of 3 milestones complete = 67%
- Shown on dashboard and reports

### Status Changes
- **Open**: Plan created, no work started
- **In Progress**: At least one milestone in progress
- **Completed**: All milestones complete
- **Overdue**: End date passed, still open

## Notifications

The system sends automatic notifications for:
- New plan assignments
- Milestone due date approaching (7 days)
- Milestone overdue
- Plan completion

Configure notification preferences in Settings → Notifications.

## POA&M Export

Export plans for reporting:

### Formats Available
- **JSON**: For programmatic integration
- **CSV**: For spreadsheet analysis
- **PDF**: For formal reporting

### Export Contents
- Plan header information
- Full milestone details
- Status and progress
- Owner and resource data

### Export Process
1. Go to Analytics → POA&M
2. Select plans to export (or select all)
3. Click **Export**
4. Choose format
5. Download file

## Standard POA&M Format

GigaChad GRC exports follow the standard POA&M format used by many auditors:

| Field | Description |
|-------|-------------|
| POA&M ID | Unique identifier |
| Weakness Description | Finding description |
| Point of Contact | Owner name and contact |
| Resources Required | Estimated effort/cost |
| Scheduled Completion | Target date |
| Milestones | Breakdown of tasks |
| Status | Current state |
| Comments | Progress notes |

## Best Practices

### Plan Creation
1. **Be Specific**: Detailed descriptions aid tracking
2. **Realistic Timelines**: Set achievable due dates
3. **Clear Ownership**: Assign specific individuals
4. **Measurable Milestones**: Define completion criteria

### Progress Tracking
1. **Regular Updates**: Update status at least weekly
2. **Document Blockers**: Note any impediments
3. **Adjust as Needed**: Update timelines if justified
4. **Communicate Changes**: Notify stakeholders of changes

### Closure
1. **Verify Completion**: Confirm all milestones done
2. **Collect Evidence**: Attach proof of completion
3. **Get Sign-off**: Obtain management approval
4. **Update Finding**: Mark original finding as remediated

## Integration with Findings

Remediation plans are linked to findings:

```
Finding: F-2024-003 - User Access Reviews Not Performed
  ↓
Remediation Plan: POA-2024-001
  ↓
Milestones: 3 tasks over 3 months
  ↓
Finding Status: In Remediation → Remediated
```

When the plan is completed:
1. System prompts to close finding
2. Finding status updates to "Remediated"
3. Closure evidence recorded
4. Audit trail maintained

## Dashboard Widget

The POA&M dashboard shows:
- **Open Plans**: Count of active plans
- **Overdue Milestones**: Items past due date
- **This Week**: Milestones due this week
- **Completion Rate**: Recent plan completion percentage

## API Reference

See the [API Documentation](/docs/API.md#remediation-plans) for programmatic access.

