# Answer Templates

Answer Templates allow you to create reusable response snippets for common questionnaire questions, significantly speeding up the questionnaire completion process.

## Overview

Answer Templates help you:
- Create standardized responses for recurring questions
- Maintain consistency across questionnaires
- Reduce time spent on repetitive answers
- Support variable substitution for customization
- Track template usage for effectiveness analysis

## Accessing Answer Templates

Navigate to **Trust → Answer Templates**

### Template List View
The main view shows:
- Template title and category
- Usage count and last used date
- Status (active/archived)
- Quick actions (edit, apply, archive)

### Search and Filter
Find templates by:
- Keyword search
- Category filter
- Status filter (active/archived)
- Sort by usage or date

## Creating Templates

### Add New Template
1. Click **Create Template**
2. Fill in template details:
   - **Title**: Descriptive name for the template
   - **Category**: Select or create a category
   - **Content**: The reusable answer text
   - **Tags**: Keywords for better searchability
   - **Variables**: Optional placeholders for customization
3. Click **Save**

### Template Variables

Use variables for dynamic content substitution:

```
Our {{company_name}} implements {{control_type}} controls 
that are reviewed {{review_frequency}}.
```

Common variables:
- `{{company_name}}` - Your organization name
- `{{date}}` - Current date
- `{{year}}` - Current year
- `{{contact_email}}` - Security contact email
- `{{certification_date}}` - Latest certification date

When applying a template, you'll be prompted to fill in variable values.

### Content Best Practices
- Write clear, professional responses
- Be specific but adaptable
- Include references to evidence or policies where applicable
- Use consistent terminology
- Review and update regularly

## Template Categories

Organize templates by category:
- **Access Control** - Authentication, authorization, identity management
- **Data Protection** - Encryption, data handling, privacy
- **Security Operations** - Monitoring, incident response, logging
- **Compliance** - Regulatory requirements, certifications, audits
- **Business Continuity** - DR, backup, availability
- **Vendor Management** - Third-party security, supply chain
- **Physical Security** - Facility access, environmental controls
- **HR & Training** - Background checks, awareness training

### Custom Categories
1. Go to template settings
2. Click **Manage Categories**
3. Add, edit, or remove categories
4. Assign colors for visual identification

## Using Templates

### In Questionnaires
When answering a questionnaire question:
1. Click **Apply Template** button
2. Search or browse available templates
3. Preview the template content
4. Click **Apply** to insert
5. Customize if needed
6. Fill in any variable values

### One-Click Apply
For frequently used templates:
1. View template in list
2. Click **Apply** button
3. Select target question(s)
4. Confirm insertion

### Bulk Apply
Apply templates to multiple questions:
1. Select questions in questionnaire
2. Click **Bulk Apply Template**
3. Map templates to questions
4. Review and confirm

## Template Management

### Editing Templates
1. Select template from list
2. Click **Edit**
3. Modify content, category, or variables
4. Click **Save**

Note: Editing a template does not affect previously applied responses.

### Archiving Templates
For outdated templates:
1. Select template
2. Click **Archive**
3. Template moves to archived list
4. Can be restored later if needed

### Restoring Archived
1. Filter by **Archived** status
2. Select template
3. Click **Restore**
4. Template becomes active

### Deleting Templates
Permanent deletion (admin only):
1. Archive template first
2. Go to archived templates
3. Click **Delete Permanently**
4. Confirm deletion

## Template Analytics

### Usage Statistics
Track template effectiveness:
- **Usage Count**: Times template was applied
- **Last Used**: Most recent application
- **User Breakdown**: Who uses which templates
- **Category Distribution**: Popular categories

### Effectiveness Metrics
Available on Trust Analytics page:
- Time savings per template
- Approval rate of responses using templates
- Templates needing updates (low usage)

## Import/Export

### Exporting Templates
1. Go to **Answer Templates**
2. Click **Export**
3. Select format (JSON/CSV)
4. Choose templates to export
5. Download file

### Importing Templates
1. Click **Import**
2. Upload JSON/CSV file
3. Review mapped fields
4. Handle duplicates (skip/merge/replace)
5. Confirm import

### Template Format
JSON structure:
```json
{
  "title": "SOC 2 Compliance Response",
  "category": "Compliance",
  "content": "Our organization has achieved SOC 2 Type II certification...",
  "tags": ["soc2", "compliance", "audit"],
  "variables": ["certification_date", "auditor_name"]
}
```

## Best Practices

### Content Quality
- Keep templates concise but complete
- Use active voice
- Avoid overly technical jargon
- Include specific metrics when possible
- Reference applicable policies or evidence

### Organization
- Use consistent naming conventions
- Apply relevant tags
- Group by logical categories
- Archive outdated templates

### Maintenance
- Review templates quarterly
- Update after policy changes
- Track usage to identify gaps
- Solicit feedback from users

### Security
- Don't include sensitive details in templates
- Use variables for confidential information
- Review templates before sharing
- Control access to template management

## Related Topics

- [Knowledge Base](knowledge-base.md)
- [Questionnaires](questionnaires.md)
- [AI-Powered Features](ai-features.md)
- [Trust Analytics](trust-analytics.md)

