# Employee Compliance Tracking

GigaChad GRC's Employee Compliance module helps you track and manage employee security training, background checks, and equipment compliance across your organization.

## Overview

Employee compliance is essential for:
- **Security Awareness**: Ensuring employees understand security policies
- **Regulatory Compliance**: Meeting training requirements (HIPAA, PCI DSS, etc.)
- **Risk Reduction**: Identifying and addressing compliance gaps
- **Audit Readiness**: Demonstrating employee training completion

## Data Sources

Employee compliance data is aggregated from multiple integrations:

| Data Type | Integrations | Evidence Collected |
|-----------|--------------|-------------------|
| **Employee Roster** | BambooHR, Workday, Gusto, ADP | Names, departments, hire dates |
| **Training Records** | KnowBe4, Proofpoint, Curricula | Course completion, scores, dates |
| **Background Checks** | Checkr, Certn, Sterling | Check status, completion dates |
| **Device Compliance** | Jamf, Intune, Kandji | Assigned devices, compliance status |
| **Access Management** | Okta, Azure AD | Systems access, MFA enrollment |

## Employee Compliance Dashboard

### Compliance Score

Organization-wide compliance score calculated from:
- Training completion rate (weighted)
- Background check status (weighted)
- Device compliance (weighted)
- Access review completion (weighted)

Weights are configurable in **Settings** → **Employee Compliance**.

### Compliance by Department

Break down compliance metrics by department:
- Overall compliance percentage
- Training completion rate
- Overdue items count

### Upcoming Deadlines

View approaching deadlines:
- Training due dates
- Background check renewals
- Access review dates
- Certification expirations

### Recent Changes

Activity feed showing:
- Newly completed training
- Background checks completed
- Compliance status changes
- New employee onboarding

## Employee Profiles

Each employee has a detailed compliance profile:

### Overview Tab
- Compliance score
- Employment information
- Department and manager
- Hire date

### Training Tab
- Assigned courses
- Completion status
- Scores achieved
- Due dates

### Background Check Tab
- Check type(s)
- Status (clear, flagged, pending)
- Completion date
- Expiration date

### Devices Tab
- Assigned devices
- Compliance status per device
- Last check-in date
- OS version

### Access Tab
- Systems with access
- Access levels
- Last access review
- MFA status

## Compliance Requirements

### Defining Requirements

Set organization-wide requirements:

1. Go to **Settings** → **Employee Compliance**
2. Configure each requirement type:

#### Training Requirements
```
- Security Awareness Training: Required annually
- Phishing Awareness: Required quarterly
- HIPAA Training: Required annually (healthcare roles)
- PCI DSS Training: Required annually (payment handlers)
```

#### Background Check Requirements
```
- Criminal Background: Required before start
- Employment Verification: Required before start
- Renewal: Every 3 years (configurable)
```

### Role-Based Requirements

Different roles may have different requirements:

| Role | Training | Background Check | Additional |
|------|----------|-----------------|------------|
| All Employees | Security Awareness | Standard | - |
| Engineering | + Secure Coding | Enhanced | Code signing |
| Finance | + Fraud Awareness | Enhanced + Credit | SOX training |
| Healthcare | + HIPAA | Enhanced | License verification |

### Configuring Role Requirements

1. Go to **Settings** → **Employee Compliance**
2. Click **Role Requirements**
3. Add or edit role configurations
4. Map roles to your HR system's job titles

## Compliance Workflows

### New Employee Onboarding

Automatic workflow when new employee detected:

```
Day 0: Employee added to HR system
  └─▶ Sync to GigaChad GRC
  
Day 1: Compliance profile created
  └─▶ Background check initiated
  └─▶ Required training assigned
  
Day 7: Training reminder sent (if incomplete)

Day 14: Escalation to manager (if incomplete)

Day 30: Final compliance check
  └─▶ Manager notified of any gaps
```

### Training Renewal

When training approaches expiration:

```
-30 days: Reminder email to employee
-14 days: Second reminder
-7 days: Manager notification
0 days: Training expired
  └─▶ Compliance score impacted
  └─▶ Escalation workflow triggered
```

### Employee Offboarding

When employee termination detected:

```
Termination detected in HR system
  └─▶ Flag for access revocation
  └─▶ Device return tracking
  └─▶ Final compliance report generated
  └─▶ Historical records preserved
```

## Reporting

### Compliance Reports

Generate reports for:

#### Training Status Report
- All employees with training status
- Completion rates by course
- Overdue training by department
- Score distributions

#### Background Check Report
- Check status for all employees
- Upcoming expirations
- Flagged results requiring review

#### Device Compliance Report
- Device inventory
- Compliance status
- Non-compliant devices
- Missing devices

### Export Options

- **PDF**: Formatted for distribution
- **Excel**: Detailed data for analysis
- **CSV**: Raw data export

### Scheduled Reports

Set up automatic reports:
1. Go to **Reports** → **Scheduled Reports**
2. Click **Add Report**
3. Select report type
4. Configure schedule (daily, weekly, monthly)
5. Add recipients
6. Save

## Integrations Setup

### HR System Integration

Connect your HR system for employee roster:

1. Go to **Integrations**
2. Find your HR system (BambooHR, Workday, etc.)
3. Configure connection
4. Enable **Employee Roster** evidence type
5. Set sync frequency (daily recommended)

### Training Platform Integration

Connect security awareness training:

1. Find your training platform (KnowBe4, Proofpoint)
2. Configure API access
3. Enable relevant evidence types:
   - Training Assignments
   - Training Completions
   - Phishing Test Results
4. Map users by email

### Background Check Integration

Connect background check provider:

1. Find your provider (Checkr, Certn)
2. Configure API credentials
3. Enable evidence types:
   - Background Check Results
   - Screening Status
4. Set up webhook for real-time updates

### MDM Integration

Connect device management:

1. Find your MDM (Jamf, Intune)
2. Configure authentication
3. Enable evidence types:
   - Device Inventory
   - Device Assignments
   - Device Compliance

## Best Practices

### 1. Automate Everything
Connect all relevant integrations for automated tracking.

### 2. Set Clear Requirements
Define exactly what training and checks are required.

### 3. Communicate Expectations
Ensure employees know their compliance responsibilities.

### 4. Monitor Proactively
Review dashboards regularly, don't wait for audits.

### 5. Act on Non-Compliance
Have clear escalation paths for non-compliant employees.

### 6. Document Exceptions
If requirements are waived, document the reason.

## Troubleshooting

### Missing Employees
- Check HR integration sync status
- Verify employee email matches across systems
- Review sync logs for errors

### Training Not Syncing
- Verify training platform integration
- Check user email matching
- Review sync frequency settings

### Incorrect Compliance Scores
- Review score weight configuration
- Check individual component scores
- Verify calculation formula

## Need Help?

- Contact support@example.com
- Review [integration guides](/help/integrations/)
- Schedule a demo with our team

---

*Last updated: December 2025*

