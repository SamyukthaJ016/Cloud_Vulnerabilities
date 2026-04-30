# Business Processes

Document and analyze your critical business processes for business continuity planning.

## Overview

Business process management helps you:
- Identify critical operations
- Perform business impact analysis (BIA)
- Define recovery objectives
- Map dependencies
- Prioritize recovery efforts

## Process List

Navigate to **BC/DR → Business Processes** to view all processes.

### Columns
- **Name**: Process name
- **Criticality**: Critical, High, Medium, Low
- **Owner**: Process owner
- **RTO**: Recovery Time Objective
- **RPO**: Recovery Point Objective
- **Status**: Active, Inactive

## Creating a Process

1. Click **Add Process**
2. Enter basic information:
   - **Name**: Process name
   - **Description**: What the process does
   - **Owner**: Responsible person
   - **Department**: Owning department
3. Set criticality assessment:
   - **Criticality Level**: How critical to business
   - **Justification**: Why this rating
4. Click **Create**

## Business Impact Analysis

### Impact Categories
Assess impact across dimensions:

| Category | Description |
|----------|-------------|
| Financial | Revenue loss, costs |
| Operational | Service delivery |
| Regulatory | Compliance violations |
| Reputational | Brand/customer trust |
| Legal | Contractual obligations |

### Impact Timeline
Estimate impact over time:
- 0-4 hours
- 4-24 hours
- 1-3 days
- 3-7 days
- 1-2 weeks
- 2+ weeks

### Conducting BIA
1. Open process detail
2. Go to **Impact Analysis** tab
3. Rate impact for each category at each time interval
4. System calculates overall criticality
5. Save analysis

## Recovery Objectives

### RTO (Recovery Time Objective)
Maximum acceptable downtime:
- How long can the process be down?
- Based on impact analysis
- Drives recovery planning

### RPO (Recovery Point Objective)
Maximum acceptable data loss:
- How much data can you lose?
- Measured in time (hours of transactions)
- Drives backup frequency

### Setting Objectives
1. Open process detail
2. Go to **Recovery Objectives** tab
3. Set RTO and RPO
4. Document assumptions
5. Get owner approval

## Dependencies

### Upstream Dependencies
What this process needs:
- Other business processes
- IT systems and applications
- Third-party services
- Key personnel

### Downstream Dependencies
What depends on this process:
- Other business processes
- Customer services
- Partner integrations

### Mapping Dependencies
1. Go to **Dependencies** tab
2. Click **Add Dependency**
3. Select dependency type
4. Link to system/process/vendor
5. Describe the relationship
6. Repeat for all dependencies

## Resources

Document required resources:

### Personnel
- Key staff roles
- Minimum staffing levels
- Skill requirements
- Succession/backup

### Technology
- Applications
- Infrastructure
- Data/databases
- Communication tools

### Facilities
- Primary location
- Alternate site
- Equipment needs

### Third Parties
- Critical vendors
- Service providers
- Contractors

## Linking to Plans

Connect processes to recovery plans:
1. Open process
2. Go to **Recovery Plans** tab
3. Link existing plans or create new
4. Document how plan addresses this process

## Reporting

### BIA Summary Report
Shows:
- All processes by criticality
- Impact assessments
- Recovery objectives
- Gaps and concerns

### Process Catalog
Complete listing with:
- Process details
- Owners
- Criticality ratings
- RTO/RPO values

## Best Practices

### Process Identification
- Interview department heads
- Review organization chart
- Map end-to-end workflows
- Don't forget support functions

### BIA Conduct
- Involve process owners
- Use consistent methodology
- Document assumptions
- Review annually

### Objective Setting
- Be realistic about capabilities
- Consider cost vs. benefit
- Align with business expectations
- Validate with stakeholders

## Related Topics

- [Recovery Plans](plans.md)
- [DR Tests](dr-tests.md)
- [BC/DR Dashboard](dashboard.md)

