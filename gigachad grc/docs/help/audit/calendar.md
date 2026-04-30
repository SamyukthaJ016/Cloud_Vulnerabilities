# Audit Calendar & Planning

The Audit Calendar provides multi-year audit planning with visual scheduling, resource allocation, and risk-based prioritization. Plan your audit program strategically and track execution.

## Overview

Calendar features include:
- **Multi-Year View**: Plan audits across multiple years
- **Quarterly Layout**: Visual organization by quarter
- **Resource Planning**: Track hours and team capacity
- **Risk Prioritization**: Schedule based on risk ratings
- **Conversion to Audits**: Turn plans into active audits

## Accessing the Calendar

Navigate to **Audit → Calendar** from the main navigation menu.

## Calendar Views

### Year View
- See all quarters for selected year
- Color-coded by audit type
- Summary counts per quarter
- Navigate between years

### Quarter View
- Detailed view of single quarter
- Individual audit entries
- Resource totals
- Status indicators

### List View
- Tabular format of all plan entries
- Sortable columns
- Filter and search
- Bulk operations

## Planning an Audit

### Create Plan Entry

1. Click **Add Plan Entry** or click on a quarter
2. Fill in planning details:

#### Basic Information
```
Audit Name: Q4 2025 SOC 2 Type II
Audit Type: SOC 2
Framework: Trust Services Criteria
Year: 2025
Quarter: Q4
```

#### Risk Assessment
```
Risk Rating: High
Rationale: Critical customer-facing systems in scope
Prior Year Findings: 3 medium findings identified
```

#### Resource Planning
```
Estimated Hours: 400
Assigned Team: 
  - Lead Auditor (200 hours)
  - Senior Auditor (120 hours)
  - Staff Auditor (80 hours)
```

#### Notes
```
Focus areas:
- New cloud migration
- Remote access controls
- Vendor management updates
```

3. Click **Save Entry**

### Plan Entry Status

- **Planned**: Initial planning stage
- **Scheduled**: Confirmed on calendar
- **In Progress**: Audit has started
- **Completed**: Audit finished
- **Deferred**: Postponed to future period

## Resource Allocation

### Capacity View

See team availability:
- Hours already allocated
- Available capacity
- Overallocation warnings

### By Quarter
```
Q1 2025:
  Total Capacity: 600 hours
  Allocated: 450 hours
  Available: 150 hours
```

### By Team Member
```
Lead Auditor:
  Q1: 200/200 hours (100%)
  Q2: 180/200 hours (90%)
  Q3: 120/200 hours (60%)
  Q4: 200/200 hours (100%)
```

## Risk-Based Scheduling

### Risk Ratings
- **Critical**: Must complete, highest priority
- **High**: Important, schedule early
- **Medium**: Standard scheduling
- **Low**: Can defer if needed

### Prioritization Factors
- Prior year findings
- System criticality
- Regulatory requirements
- Management requests
- Time since last audit

### Automatic Suggestions

The system can suggest scheduling based on:
- Risk ratings
- Available capacity
- Framework requirements
- Historical patterns

## Converting to Active Audit

When ready to start:

1. Open the plan entry
2. Click **Convert to Audit**
3. Confirm audit details:
   - Start date
   - End date
   - Team assignment
   - Scope details
4. Click **Create Audit**

The plan entry:
- Status changes to "In Progress"
- Links to the new audit
- Actual dates begin tracking

## Calendar Features

### Drag and Drop
- Move entries between quarters
- Reschedule with visual feedback
- Confirmation before saving

### Color Coding
- By audit type
- By risk rating
- By status
- Customizable

### Filtering
- By audit type
- By team member
- By risk rating
- By status

### Search
- Find entries by name
- Filter by framework
- Search notes content

## Annual Planning Process

### Step 1: Risk Assessment
1. Review prior year audits
2. Identify high-risk areas
3. Consider regulatory changes
4. Gather stakeholder input

### Step 2: Draft Calendar
1. Add critical/high risk audits first
2. Balance across quarters
3. Consider resource constraints
4. Leave buffer for ad-hoc

### Step 3: Resource Allocation
1. Assign teams to audits
2. Check capacity
3. Adjust as needed
4. Document assignments

### Step 4: Approval
1. Present to leadership
2. Get budget approval
3. Finalize calendar
4. Communicate to teams

### Step 5: Execute & Monitor
1. Convert to audits as dates approach
2. Track against plan
3. Adjust for changes
4. Report on progress

## Reporting

### Annual Audit Plan Report
- Full year calendar
- Resource allocation summary
- Risk distribution
- Comparison to prior year

### Quarterly Status Report
- Planned vs actual
- Completion rates
- Variance analysis
- Next quarter preview

### Resource Utilization Report
- Hours planned vs actual
- Utilization by team member
- Over/under allocation

## Integration

### With Audits
- Plan entries link to audits
- Actual dates sync back
- Status updates automatically

### With Templates
- Reference templates when planning
- Estimate hours from template

### With Analytics
- Planning metrics in analytics
- Trend analysis
- Forecasting

## Best Practices

1. **Start Early**: Plan at least one quarter ahead
2. **Be Realistic**: Don't over-commit capacity
3. **Build Buffer**: Leave room for ad-hoc requests
4. **Regular Review**: Update plans monthly
5. **Communicate**: Share calendar with stakeholders
6. **Document Changes**: Track plan modifications
7. **Learn and Adjust**: Use actuals to improve estimates

## API Reference

See the [API Documentation](/docs/API.md#audit-planning) for programmatic access to calendar data.

