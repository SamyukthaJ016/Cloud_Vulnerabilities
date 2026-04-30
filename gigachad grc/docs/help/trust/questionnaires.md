# Questionnaires

The Questionnaires module helps you efficiently manage and respond to security questionnaires from customers, prospects, and partners.

## Overview

The Questionnaires module enables you to:
- Receive and track security questionnaires
- Assign questions to subject matter experts
- Leverage Knowledge Base for consistent answers
- Use AI to draft responses quickly
- Export completed questionnaires
- Track SLAs and deadlines

## Accessing Questionnaires

Navigate to **Trust → Questionnaires**

### List View
The main view displays:
- Questionnaire title and requester
- Status and progress
- Due date and priority
- Assigned analyst
- Quick actions

### Filters
Filter questionnaires by:
- **Status**: Pending, In Progress, Completed
- **Priority**: Urgent, High, Normal, Low
- **Assignee**: Specific analyst or team
- **Date Range**: Received or due date
- **Requester**: Company name

## Questionnaire Lifecycle

### Status Flow
```
Received → In Progress → Under Review → Completed
              ↓
           On Hold
```

### Status Definitions

| Status | Description |
|--------|-------------|
| **Received** | New questionnaire, not yet started |
| **In Progress** | Being actively worked on |
| **Under Review** | Answers complete, awaiting review |
| **On Hold** | Paused, waiting for input |
| **Completed** | Finalized and ready to return |

## Creating Questionnaires

### Manual Creation
1. Click **New Questionnaire**
2. Enter details:
   - Requester name and company
   - Due date
   - Priority
   - Description
3. Add questions manually or import

### Import Questions
Upload questions from file:
1. Click **Import Questions**
2. Select file format:
   - CSV
   - Excel (.xlsx)
   - Text file
3. Map columns (question, category, etc.)
4. Review and confirm

### Supported Import Formats

#### CSV Format
```csv
Question,Category,Notes
"Do you encrypt data at rest?","Encryption",""
"What is your backup frequency?","Business Continuity",""
```

#### Excel Format
Column headers: Question, Category, Section, Notes

#### Text Format
One question per line, or use markers for structure

## Working with Questions

### Question Workspace

The question workspace provides a split-panel view:
- **Left Panel**: Question list and navigation
- **Right Panel**: Answer editing and tools

### Answering Questions

1. Select a question from the list
2. View question details and context
3. Use one of these methods to answer:
   - Type answer manually
   - Apply Knowledge Base suggestion
   - Use Answer Template
   - Generate AI draft
4. Add supporting notes if needed
5. Mark question as complete

### Answer Tools

#### Knowledge Base Panel
- Shows relevant KB articles
- One-click insert
- Search KB manually
- Create new KB article from answer

#### Answer Templates
- Browse available templates
- Search by keyword/category
- Preview before applying
- Fill in variables

#### AI Assistant
- Click **Draft with AI**
- Review generated answer
- Edit and customize
- Accept or regenerate

### Question Status

Per-question status:
- **Pending**: Not yet addressed
- **In Progress**: Being worked on
- **Answered**: Response provided
- **Approved**: Reviewed and confirmed
- **Skipped**: N/A or declined

### Bulk Actions

For multiple questions:
- Bulk assign to analyst
- Bulk categorize
- Bulk apply template
- Bulk mark complete

## Similar Question Detection

### Finding Duplicates

Within a questionnaire:
1. Click **Check for Duplicates**
2. View flagged questions
3. Link duplicate questions
4. Answer once, apply to all

### Cross-Questionnaire Search

Find similar questions from past:
1. Select a question
2. Click **Find Similar**
3. View matches with answers
4. Copy successful answers

### Similarity Score

Questions ranked by relevance:
- **90%+**: Very similar
- **70-90%**: Related
- **50-70%**: Possibly relevant

## Questionnaire Export

### Export Formats

Export completed questionnaires:
- **Excel (.xlsx)**: Formatted spreadsheet
- **CSV**: Plain data export
- **JSON**: Structured data
- **PDF**: Formatted document

### Export Options

1. Go to questionnaire detail
2. Click **Export**
3. Select format
4. Choose options:
   - Include notes
   - Include evidence references
   - Include metadata
5. Download file

### Bulk Export

Export multiple questionnaires:
1. Select questionnaires in list
2. Click **Export Selected**
3. Choose format and options
4. Download ZIP archive

### Export Templates

Save export preferences:
1. Configure export options
2. Click **Save as Template**
3. Name your template
4. Reuse for future exports

## Dashboard Queue Widget

The Trust Analyst Queue appears on the main dashboard showing:
- Questions assigned to you
- Overdue items (highlighted)
- Items due this week
- High priority items

### Queue Features
- Quick-access to assigned questions
- Status at a glance
- One-click navigation
- Overdue alerts

## Collaboration

### Comments

Add comments to questions:
- Internal notes
- Collaboration with team
- Review feedback
- Change history

### Assignments

Assign questions to SMEs:
1. Select question(s)
2. Click **Assign**
3. Choose analyst
4. Add assignment note
5. Analyst is notified

### Review Workflow

For quality control:
1. Analyst completes answers
2. Submit for review
3. Reviewer checks responses
4. Approve or request changes
5. Questionnaire completed

## Deadlines & SLAs

### Due Dates

Set and track deadlines:
- Questionnaire-level due date
- Question-level due dates (optional)
- Visual countdown
- Overdue highlighting

### SLA Tracking

Automatic SLA monitoring:
- Green: On track
- Yellow: At risk (>75% of time used)
- Red: Overdue

### Notifications

Automatic alerts for:
- Approaching deadline
- At-risk items
- Overdue questionnaires
- Assignment changes

## Metrics & Reporting

### Per-Questionnaire Metrics
- Completion percentage
- Time spent
- Questions by status
- Answer sources used

### Analytics Integration
View in Trust Analytics:
- Response time trends
- SLA compliance
- Team performance
- Category analysis

## Best Practices

### Efficient Processing
1. Review all questions first
2. Categorize for routing
3. Check for similar/duplicate
4. Use KB and templates
5. Leverage AI for drafts

### Quality Assurance
- Review before completing
- Verify accuracy
- Check for consistency
- Include evidence references

### Team Coordination
- Assign by expertise
- Set clear deadlines
- Use comments for collaboration
- Monitor workload

### Knowledge Building
- Add good answers to KB
- Create templates from patterns
- Document common questions
- Build institutional knowledge

## Troubleshooting

### Import Failures
- Check file format
- Verify column headers
- Review for special characters
- Check file encoding (UTF-8)

### Missing Questions
- Check filters
- Verify import completed
- Review error logs

### Export Issues
- Check questionnaire status
- Verify all questions answered
- Try different format

## Related Topics

- [Knowledge Base](knowledge-base.md)
- [Answer Templates](answer-templates.md)
- [AI Features](ai-features.md)
- [Trust Analytics](trust-analytics.md)
- [Trust Configuration](trust-configuration.md)

