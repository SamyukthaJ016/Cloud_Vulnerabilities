# Controls Management

Controls are the security measures your organization implements to meet compliance requirements and mitigate risks. This guide covers everything you need to know about managing controls in GigaChad GRC.

## Overview

The Controls module allows you to:
- Maintain a library of security controls
- Track implementation status
- Map controls to compliance frameworks
- Link evidence to demonstrate implementation
- Schedule and record control testing

## Viewing Controls

### Controls List
Navigate to **Compliance → Controls** to see all controls:

- **Search**: Filter by control title or ID
- **Category Filter**: Filter by control category (Access Control, Data Protection, etc.)
- **Status Filter**: Filter by implementation status
- **Framework Filter**: Show controls for a specific framework

### Control Categories
Controls are organized by security domains:
- Access Control
- Asset Management
- Cryptography
- Human Resources Security
- Incident Management
- Network Security
- Operations Security
- Physical Security
- Risk Management
- Supplier Relationships
- System Development

## Creating Controls

### Add a Single Control
1. Click **Add Control**
2. Fill in the required fields:
   - **Control ID**: Unique identifier (e.g., AC-001)
   - **Title**: Descriptive name
   - **Description**: Detailed explanation
   - **Category**: Security domain
3. Optional fields:
   - **Owner**: Responsible person
   - **Implementation Status**: Current state
   - **Testing Frequency**: How often to test
   - **Framework Mappings**: Which frameworks require this control
4. Click **Save**

### Bulk Upload Controls
1. Click **Bulk Upload**
2. Download the CSV template
3. Fill in control data in the spreadsheet
4. Upload the completed CSV
5. Review and confirm the import

## Control Statuses

| Status | Description |
|--------|-------------|
| **Not Started** | Control has not been implemented |
| **In Progress** | Implementation is underway |
| **Implemented** | Control is fully implemented |
| **Not Applicable** | Control doesn't apply to your organization |

## Control Detail Page

Click any control to view its details:

### Information Tab
- Basic control information
- Owner and assignments
- Implementation notes

### Evidence Tab
- Linked evidence artifacts
- Upload new evidence
- Evidence status and expiration

### Testing Tab
- Testing history
- Schedule next test
- Record test results

### Framework Mappings Tab
- Which frameworks require this control
- Requirement details
- Gap analysis

### Activity Tab
- Change history
- Comments and discussions

## Linking Evidence

Evidence demonstrates that a control is implemented:

1. Open the control detail page
2. Go to the **Evidence** tab
3. Click **Link Evidence**
4. Select existing evidence or upload new
5. Add notes explaining the relevance

### Evidence Types
- Screenshots
- Policy documents
- Configuration exports
- Audit reports
- Certificates
- Logs

## Control Testing

Regular testing validates that controls remain effective:

### Schedule a Test
1. Open the control
2. Go to **Testing** tab
3. Click **Schedule Test**
4. Set test date and assignee
5. Add test instructions

### Record Test Results
1. Open the scheduled test
2. Select result: **Pass**, **Fail**, or **Partial**
3. Add observations
4. Upload supporting evidence
5. Save results

### Testing Frequency
Common testing frequencies:
- **Annual**: Yearly review
- **Semi-Annual**: Every 6 months
- **Quarterly**: Every 3 months
- **Monthly**: Every month
- **Continuous**: Automated monitoring

## Framework Mapping

Controls map to compliance framework requirements:

### View Mappings
1. Open any control
2. Go to **Framework Mappings** tab
3. See which frameworks require this control

### Add a Mapping
1. Click **Add Mapping**
2. Select the framework
3. Select the specific requirement
4. Save the mapping

### Pre-Loaded Mappings
GigaChad GRC includes pre-loaded controls for:
- SOC 2 Type II
- ISO 27001:2022
- NIST CSF 2.0
- PCI DSS
- HIPAA

## Best Practices

### Control Ownership
- Assign a clear owner to each control
- Owners are responsible for implementation and evidence

### Regular Review
- Review control status quarterly
- Update implementation notes as changes occur
- Keep evidence current

### Evidence Quality
- Upload dated evidence
- Include screenshots with timestamps
- Document configuration settings
- Maintain evidence versioning

### Gap Analysis
- Review framework readiness regularly
- Prioritize high-risk gaps
- Create remediation plans for missing controls

## Export and Reporting

### Export Controls
1. Click **Export** on the controls list
2. Choose format (CSV or PDF)
3. Download the file

### Control Reports
- **Implementation Summary**: Status breakdown
- **Gap Analysis**: Missing controls by framework
- **Testing Schedule**: Upcoming and overdue tests

## Related Topics

- [Framework Management](managing-frameworks.md)
- [Evidence Collection](evidence.md)
- [Compliance Calendar](calendar.md)

