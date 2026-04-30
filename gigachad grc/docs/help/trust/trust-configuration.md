# Trust Configuration

Trust Configuration allows administrators to customize the behavior of the Trust module, including SLA settings, AI configuration, assignment rules, and more.

## Overview

Trust Configuration controls:
- Service Level Agreement (SLA) settings
- Question assignment automation
- Knowledge Base behavior
- Trust Center appearance
- AI integration settings

## Accessing Configuration

Navigate to **Settings → Trust Configuration**

### Permission Requirements
Trust Configuration requires:
- Admin role, or
- `trust:configure` permission

## SLA Settings

Service Level Agreement settings define response time targets and escalation rules.

### Response Time Targets

Configure target completion times by priority:

| Priority | Default Target | Description |
|----------|---------------|-------------|
| **Urgent** | 24 hours | Critical customer, deal-closing |
| **High** | 3 business days | Important deadline |
| **Normal** | 5 business days | Standard request |
| **Low** | 10 business days | No urgency |

#### Configuring Targets
1. Go to **SLA Settings** tab
2. Set target hours for each priority
3. Enable/disable business hours only
4. Click **Save**

### Business Hours

Define when SLA clock runs:
- **Business days**: Monday-Friday (default)
- **Custom**: Select specific days
- **Business hours**: 9 AM - 5 PM (default)
- **Timezone**: Your organization's timezone

### Escalation Rules

Configure automatic escalations:

#### Warning Threshold
- Percentage of SLA consumed before warning
- Default: 75%
- Triggers yellow status indicator

#### Escalation Actions
When SLA is at risk:
- Email notification to analyst
- Email to manager
- Slack notification
- Priority boost

#### Breach Actions
When SLA is breached:
- Alert to leadership
- Auto-reassignment option
- Incident logging

## Assignment Settings

Control how questions are assigned to analysts.

### Assignment Mode

Choose from:
- **Manual**: Admin assigns all questions
- **Round Robin**: Rotate among team
- **Load Balanced**: Based on current workload
- **Category-Based**: By expertise area
- **Hybrid**: Combine methods

### Auto-Assignment Rules

#### Enable Auto-Assignment
1. Toggle **Auto-Assign Questions**
2. Configure assignment criteria
3. Set fallback assignee

#### Category Routing
Map categories to analysts:
1. Go to **Category Assignment**
2. Select category
3. Assign primary and backup analysts
4. Save configuration

#### Workload Limits
Prevent overloading:
- **Max concurrent questions**: Per analyst limit
- **Daily assignment cap**: Maximum new assignments
- **Queue threshold**: Pause assignments when reached

### Skill Matching

Match questions to expertise:
1. Define analyst skills/categories
2. Enable **Skill-Based Assignment**
3. Questions route to matching analysts

## Knowledge Base Settings

Configure Knowledge Base behavior.

### Search Settings

#### Relevance Threshold
Minimum match score for suggestions:
- High (80%): Only strong matches
- Medium (60%): Balanced
- Low (40%): More suggestions

#### Auto-Suggest
- **Enable auto-suggest**: Show KB matches automatically
- **Suggest count**: Number of suggestions to show (default: 5)
- **Category weighting**: Prioritize same-category matches

### Content Linking

#### Auto-Link to Controls
Automatically link KB articles to:
- Control implementations
- Evidence items
- Policy documents

#### Cross-Reference
Enable finding related content:
- Similar KB articles
- Related questionnaire answers
- Connected policies

### Visibility Defaults

Default visibility for new articles:
- Internal only
- Trust Center - Public
- Trust Center - NDA Required

## Trust Center Settings

Configure public Trust Center appearance and behavior.

### General Settings

- **Enable Trust Center**: Toggle public availability
- **Custom Domain**: Set your trust center URL
- **Default Language**: Primary language
- **Theme**: Light/Dark/Auto

### Branding

- **Logo**: Upload company logo
- **Favicon**: Browser tab icon
- **Primary Color**: Brand color
- **Secondary Color**: Accent color

### Content Sections

Enable/disable sections:
- Company Profile
- Certifications
- Documents
- FAQ
- Contact Form

### Access Control

- **Public Access**: Anyone can view
- **NDA Required**: For sensitive content
- **Request Access**: Manual approval

### SEO Settings

- **Meta title**: Browser title
- **Meta description**: Search preview
- **Robots**: Allow/disallow indexing

## AI Settings

Configure AI-powered features.

### AI Provider

Select and configure AI provider:

#### OpenAI
1. Select **OpenAI** provider
2. Enter API key
3. Choose model:
   - GPT-4 (highest quality)
   - GPT-4 Turbo (faster)
   - GPT-3.5 Turbo (cost-effective)

#### Anthropic
1. Select **Anthropic** provider
2. Enter API key
3. Choose model:
   - Claude 3 Opus
   - Claude 3 Sonnet
   - Claude 3 Haiku

### AI Features Toggle

Enable/disable specific AI features:
- **Smart Answer Drafting**: AI generates answers
- **Question Categorization**: Auto-categorize questions
- **Similar Question Detection**: Find related questions
- **Answer Improvement**: AI enhancement suggestions

### AI Behavior

#### Confidence Threshold
Minimum confidence to show suggestions:
- High: Only show confident answers
- Low: Show more suggestions

#### Privacy Mode
Protect sensitive data:
- Mask company names
- Redact numbers
- Remove email addresses

#### Context Limits
Control what AI accesses:
- KB articles only
- Include past answers
- Include templates

### Rate Limiting

Control AI usage:
- **Daily limit**: Max AI calls per day
- **Per-user limit**: Individual quotas
- **Cost alerts**: Budget notifications

## Dashboard Queue Widget

Configure the Trust Analyst Queue widget on the main dashboard.

### Widget Display
- **Enable widget**: Show on dashboard
- **Default expanded**: Start expanded/collapsed
- **Max items shown**: Limit visible items

### Queue Filters
What appears in queue:
- Assigned to me only
- Team assignments
- All organization

### Priority Display
Visual indicators:
- Color coding by priority
- Overdue highlighting
- Due date warnings

## Notification Settings

Configure Trust module notifications.

### Notification Events

Enable notifications for:
- New questionnaire received
- Question assigned
- SLA warning
- SLA breach
- Questionnaire completed
- Comment added

### Notification Channels

For each event:
- In-app notification
- Email notification
- Slack/Teams notification

### Digest Options

- Real-time: Immediate notifications
- Hourly digest: Batched every hour
- Daily digest: Once per day

## Integration Settings

### API Access

- **API enabled**: Allow API access
- **Rate limits**: Requests per minute
- **Allowed IPs**: Restrict access

### Webhooks

Configure outbound webhooks:
- Questionnaire events
- SLA events
- Completion events

## Defaults & Templates

### Default Templates

Set default templates for:
- New questionnaire welcome message
- Completion notification
- Request access response

### Field Defaults

Default values for new questionnaires:
- Priority: Normal
- Category: General
- Assignment: Unassigned

## Audit & Compliance

### Audit Logging

All configuration changes are logged:
- Who made the change
- What was changed
- When it occurred
- Previous value

### Export Configuration

Export settings for:
- Backup purposes
- Environment replication
- Audit compliance

## Best Practices

### Initial Setup
1. Configure SLA targets first
2. Set up assignment rules
3. Configure AI if using
4. Customize notifications

### Ongoing Management
- Review settings quarterly
- Adjust based on analytics
- Update as team changes
- Monitor AI effectiveness

### Security
- Limit configuration access
- Review audit logs regularly
- Protect API keys
- Monitor integrations

## Troubleshooting

### Common Issues

#### AI Not Working
- Check API key validity
- Verify provider status
- Review rate limits

#### Assignments Not Working
- Verify assignment rules
- Check analyst availability
- Review workload limits

#### SLA Calculations Wrong
- Confirm timezone settings
- Check business hours config
- Verify holiday calendar

## Related Topics

- [Trust Analytics](trust-analytics.md)
- [Answer Templates](answer-templates.md)
- [AI Features](ai-features.md)
- [Questionnaires](questionnaires.md)

