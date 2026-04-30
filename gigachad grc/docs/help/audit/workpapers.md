# Workpaper Management

Workpapers are the formal documentation that supports audit conclusions. GigaChad GRC provides comprehensive workpaper management with version control, review workflows, and cross-referencing.

## Overview

Audit workpapers provide:
- **Documentation Trail**: Evidence of work performed
- **Review Support**: Multi-level approval process
- **Quality Control**: Version tracking and sign-offs
- **Cross-References**: Links to controls, findings, and evidence

## Accessing Workpapers

1. Navigate to **Audit → Workpapers** for all workpapers
2. Or from a specific audit, go to the **Workpapers** tab

## Workpaper Structure

Each workpaper includes:

### Header Information
- **Workpaper Number**: Unique identifier (e.g., WP-001)
- **Title**: Descriptive name
- **Audit**: Parent audit association
- **Status**: Current workflow stage

### Content
- **Rich Text Editor**: Format content with headings, lists, tables
- **Markdown Support**: For advanced formatting
- **Attachments**: Upload supporting files

### Sign-offs
- **Prepared By**: Initial preparer
- **Reviewed By**: Reviewer signature
- **Approved By**: Final approval

## Workflow States

```
Draft → Pending Review → Reviewed → Approved
                ↓
            Rejected (returns to Draft)
```

### Draft
- Initial creation stage
- Preparer can edit freely
- Not visible to external auditors

### Pending Review
- Submitted for review
- Preparer cannot edit
- Reviewer notified

### Reviewed
- Reviewer has signed off
- Ready for final approval
- Senior team member notified

### Approved
- Fully approved workpaper
- Locked from further edits
- Part of final audit record

### Rejected
- Returned with comments
- Goes back to Draft status
- Preparer addresses feedback

## Creating a Workpaper

1. Click **Create Workpaper** button
2. Enter workpaper details:
   - **Workpaper Number**: Auto-generated or custom
   - **Title**: Clear, descriptive title
   - **Audit**: Select the parent audit

3. Write the content:
   - Use the rich text editor
   - Include objectives, procedures, results
   - Add tables, lists, and formatting

4. Attach supporting files if needed

5. Click **Save as Draft** or **Submit for Review**

## Version Control

Workpapers maintain full version history:

- **Automatic Versioning**: Each save creates a new version
- **Version Comparison**: View differences between versions
- **Rollback**: Restore previous versions if needed
- **Change Log**: See who changed what and when

To view version history:
1. Open the workpaper
2. Click **Version History** tab
3. Select versions to compare or restore

## Sign-off Process

### Preparer Sign-off
1. Complete the workpaper content
2. Review your work
3. Click **Submit for Review**
4. System records your digital signature

### Reviewer Sign-off
1. Open workpaper assigned for review
2. Review content and attachments
3. Click **Sign Off as Reviewed** or **Request Changes**
4. If approved, system records signature and advances status

### Approver Sign-off
1. Open workpaper pending approval
2. Final review of content and prior sign-offs
3. Click **Approve** or **Reject**
4. System records final signature

## Cross-References

Link workpapers to related items:

### To Controls
```
Reference: CTRL-001 - Access Control Policy
```

### To Findings
```
Reference: FIND-003 - Missing User Access Review
```

### To Evidence
```
Reference: EVD-045 - Screenshot of access logs
```

### To Other Workpapers
```
Reference: WP-002 - General IT Controls Testing
```

## Best Practices

1. **Clear Naming**: Use descriptive workpaper numbers and titles
2. **Standard Format**: Follow a consistent structure
3. **Complete Documentation**: Include objective, procedures, and conclusions
4. **Timely Review**: Don't let workpapers sit in pending review
5. **Cross-Reference Everything**: Link to related controls, evidence, findings

## Sample Workpaper Structure

```markdown
# WP-001: Access Management Controls Testing

## 1. Objective
Test the design and operating effectiveness of user access 
management controls for the audit period.

## 2. Scope
- User provisioning process
- Periodic access reviews
- Termination procedures

## 3. Procedures Performed
1. Obtained access request tickets for sample of 25 new hires
2. Verified manager approval on each request
3. Confirmed access matched approved request

## 4. Results
24 of 25 samples met all criteria. 1 exception noted:
- User ID 12345: Access granted before manager approval
- See Finding F-003

## 5. Conclusion
Control is operating effectively with minor exceptions.
Management has implemented enhanced controls.

## 6. Attachments
- Access request tickets (25)
- Manager approval emails (24)
- Exception documentation

## 7. References
- Control: CTRL-ACCESS-001
- Finding: F-003
- Evidence: EVD-ACCESS-001 through EVD-ACCESS-025
```

## API Reference

See the [API Documentation](/docs/API.md#audit-workpapers) for programmatic access.

