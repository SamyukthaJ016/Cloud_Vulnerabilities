# Asset Management

Track and manage your organization's IT assets and their security classification.

## Overview

Asset Management helps you:
- Maintain asset inventory
- Classify asset criticality
- Track asset ownership
- Link to controls and risks
- Support business continuity

## Asset Types

| Type | Examples |
|------|----------|
| **Hardware** | Servers, laptops, network equipment |
| **Software** | Applications, databases, platforms |
| **Data** | Databases, file shares, cloud storage |
| **Network** | VPNs, firewalls, load balancers |
| **Cloud** | SaaS applications, cloud services |
| **Physical** | Data centers, offices |

## Asset List

Navigate to **Data → Assets** to view all assets.

### Columns
- **Name**: Asset name
- **Type**: Asset category
- **Criticality**: Critical, High, Medium, Low
- **Owner**: Responsible person
- **Status**: Active, Retired, Planned
- **Environment**: Production, Development, etc.

### Filters
- **Type**: Filter by asset type
- **Criticality**: By importance
- **Owner**: By owner
- **Status**: Active, Retired

## Adding Assets

### Single Asset
1. Click **Add Asset**
2. Enter basic information:
   - **Name**: Asset identifier
   - **Type**: Asset category
   - **Description**: Asset details
   - **Owner**: Responsible person
3. Classification:
   - **Criticality**: Business importance
   - **Data Classification**: Data sensitivity
   - **Environment**: Where it operates
4. Click **Create**

### Bulk Import
1. Click **Add Asset** → **Bulk Import**
2. Download CSV template
3. Fill in asset details
4. Upload and confirm

### Integration Import
Import from:
- Cloud providers (AWS, Azure, GCP)
- CMDB systems
- Discovery tools

## Asset Classification

### Criticality Levels

| Level | Description | Recovery Priority |
|-------|-------------|-------------------|
| **Critical** | Business-critical, immediate impact | Highest |
| **High** | Important, significant impact | High |
| **Medium** | Standard business support | Medium |
| **Low** | Non-essential | Low |

### Data Classification
If asset contains data:
- **Public**: No restrictions
- **Internal**: Internal use only
- **Confidential**: Limited access
- **Restricted**: Highly sensitive

## Asset Detail Page

Click any asset to see:

### Overview
- Asset information
- Classification
- Ownership

### Technical Details
- Technical specifications
- Network information
- Dependencies

### Relationships
- Linked controls
- Associated risks
- Dependent processes
- Related vendors

### Compliance
- Framework requirements
- Control mappings
- Evidence links

### Activity
- Change history
- Status changes
- Notes

## Asset Relationships

### Dependencies
Document what the asset depends on:
- Upstream systems
- Network dependencies
- Data feeds
- Third-party services

### Dependents
Document what depends on this asset:
- Downstream systems
- Business processes
- Other assets

### Linking Assets
1. Open asset detail
2. Go to **Relationships** tab
3. Click **Add Relationship**
4. Select related asset
5. Define relationship type

## Lifecycle Management

### Asset Status
- **Planned**: Future asset
- **In Development**: Being built
- **Active**: In production
- **Retiring**: Being phased out
- **Retired**: No longer active

### Status Changes
Track asset lifecycle:
1. Click **Change Status**
2. Select new status
3. Add notes
4. Confirm

## Risk Association

### Link to Risks
Associate assets with risks:
1. Go to **Risks** tab
2. Click **Link Risk**
3. Select relevant risks
4. Document impact

### Risk Indicators
View risk exposure:
- Linked risks by severity
- Control coverage
- Compliance status

## Reporting

### Asset Inventory Report
Complete listing with:
- All asset details
- Classifications
- Ownership
- Status

### Risk Exposure Report
Assets and their risks:
- High-risk assets
- Uncontrolled assets
- Compliance gaps

### Export
Export for analysis:
1. Apply filters
2. Click **Export**
3. Download CSV/PDF

## Best Practices

### Inventory Management
- Keep information current
- Regular ownership verification
- Document all assets
- Remove retired assets

### Classification
- Apply consistent criteria
- Review classifications annually
- Update for changes
- Document rationale

### Documentation
- Complete technical details
- Map dependencies
- Link to processes
- Track changes

## Related Topics

- [Controls Management](../compliance/controls.md)
- [Risk Management](../risk-management/creating-risks.md)
- [Business Processes](../bcdr/business-processes.md)

