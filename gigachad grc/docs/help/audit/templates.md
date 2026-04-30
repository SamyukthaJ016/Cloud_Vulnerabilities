# Audit Templates

Audit templates allow you to create reusable audit programs with pre-defined checklists, evidence requests, and test procedures. This saves time and ensures consistency across similar audits.

## Overview

Templates capture the structure and requirements of common audit types, making it easy to spin up new audits with a single click. GigaChad GRC includes system templates for popular frameworks and allows you to create custom templates.

## Accessing Templates

Navigate to **Audit → Templates** from the main navigation menu.

## System Templates

GigaChad GRC includes built-in templates for common frameworks:

### SOC 2 Type II
- Full audit program covering Trust Services Criteria
- Pre-defined evidence requests for each control category
- Test procedures aligned with AICPA standards
- Common Point of Focus checklists

### ISO 27001
- Comprehensive controls from Annex A
- Evidence requirements per control objective
- Statement of Applicability support
- Risk-based test procedures

### HIPAA Security Rule
- Administrative, Physical, and Technical safeguards
- Required vs. Addressable implementation checklists
- PHI handling evidence requirements
- Business Associate compliance checks

### PCI-DSS
- All 12 requirements covered
- Compensating controls documentation
- Evidence mapping for each requirement
- Quarterly and annual testing schedules

## Creating Custom Templates

1. Click **Create Template** button
2. Fill in template details:
   - **Name**: Descriptive template name
   - **Description**: Purpose and scope
   - **Audit Type**: Select or enter custom type
   - **Framework**: Optional framework association

3. Add **Checklist Items**:
   - Planning tasks
   - Fieldwork activities
   - Reporting requirements

4. Add **Request Templates**:
   - Pre-defined evidence requests
   - Categories for organization
   - Default priorities and due dates

5. Add **Test Procedure Templates**:
   - Standard test procedures
   - Sample size and selection guidance
   - Expected results

6. Click **Save Template**

## Cloning a Template to an Audit

1. From the Templates list, find the template you want to use
2. Click the **Clone to Audit** button (or the three-dot menu → Clone)
3. Enter the audit name (e.g., "Q4 2024 SOC 2 Type II Audit")
4. Click **Create Audit**

The system will:
- Create a new audit with the template's settings
- Generate all checklist items
- Create evidence requests from templates
- Add test procedures ready for execution

## Template Management

### Editing Templates
- Click on a template to view details
- Click **Edit** to modify
- Changes don't affect audits already created from the template

### Archiving Templates
- Archive templates no longer in use
- Archived templates won't appear in the main list
- Can be restored if needed

### Deleting Templates
- Only custom templates can be deleted
- System templates cannot be removed
- Deleting a template doesn't affect existing audits

## Best Practices

1. **Start with System Templates**: Use system templates as a base, then customize
2. **Document Variations**: Create separate templates for different scope variations
3. **Include Time Estimates**: Add time estimates to test procedures for planning
4. **Regular Updates**: Review and update templates as standards change
5. **Naming Convention**: Use clear, descriptive names (e.g., "SOC 2 - Security Only")

## API Reference

See the [API Documentation](/docs/API.md#audit-templates) for programmatic access to templates.

