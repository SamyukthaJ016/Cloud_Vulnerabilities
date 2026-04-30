# MCP Server Quick Start Guide

## What are MCP Servers?

Model Context Protocol (MCP) servers automate GRC workflows by connecting to external services to:

- **Collect Evidence**: Automatically gather compliance evidence from AWS, Azure, GitHub, Okta, and more
- **Run Compliance Checks**: Validate controls against SOC 2, ISO 27001, HIPAA, and GDPR requirements
- **AI-Powered Analysis**: Use AI to analyze risks, draft policies, and suggest controls

## Available Server Types

### Built-in GRC Servers

| Server | Purpose | Key Integrations |
|--------|---------|------------------|
| **GRC Evidence Collection** | Automated evidence gathering | AWS, Azure, GitHub, Okta, Google Workspace, Jamf |
| **GRC Compliance Automation** | Control testing & gap analysis | Internal GRC data |
| **GRC AI Assistant** | Risk analysis & policy drafting | OpenAI, Anthropic |

### External MCP Servers

| Server | Purpose | Required Config |
|--------|---------|-----------------|
| **GitHub** | Repository security scanning | `GITHUB_TOKEN` |
| **Slack** | Notifications & alerts | `SLACK_BOT_TOKEN` |
| **PostgreSQL** | Database queries | `DATABASE_URL` |
| **Filesystem** | Local file access | Optional paths |
| **Puppeteer** | UI screenshot capture | None |
| **Memory** | AI context persistence | None |

## Step-by-Step Setup

### 1. Navigate to MCP Settings

Go to **Settings → MCP Servers** in the sidebar.

### 2. Add a New Server

Click **"Add Server"** to open the template selection modal.

### 3. Select a Template

Choose the server type you want to deploy. Each template shows:
- Description of capabilities
- Required vs optional credentials
- Evidence types collected

### 4. Configure Credentials

#### For GRC Evidence Collection Server:

Expand each integration section and enter credentials:

**AWS** (for IAM, CloudTrail, Security Groups)
```
AWS_ACCESS_KEY_ID: Your AWS access key
AWS_SECRET_ACCESS_KEY: Your AWS secret key
AWS_REGION: us-east-1 (default)
```

**GitHub** (for repository security)
```
GITHUB_TOKEN: ghp_xxxxxxxxxxxx (Personal Access Token)
```

**Okta** (for IAM evidence)
```
OKTA_DOMAIN: yourcompany.okta.com
OKTA_API_TOKEN: Your Okta API token
```

> 💡 **Tip**: Only configure the integrations you need. Leave others blank.

### 5. Deploy the Server

Click **"Deploy Server"** to create the server instance.

### 6. Connect the Server

After deployment, click the **Play** button to start the server.

### 7. View Server Details

Click on the server row to see:
- Server status and configuration
- Configured integrations
- Evidence types being collected
- Available tools and resources

## Credential Security

### How Credentials are Protected

✅ **Encrypted at rest** using AES-256-GCM
✅ **Never exposed** via API (only masked versions shown)
✅ **Audit tracked** with creator and timestamp
✅ **Stored securely** in encrypted database

### For Auditors

When an auditor asks about evidence collection, show them:

1. **Server Details Modal** → Shows configured integrations
2. **Credential Configuration Status** → Shows which providers are active
3. **Evidence Types Collected** → Lists all data being gathered
4. **Created By / Created At** → Audit trail information

## Common Configurations

### Minimal AWS Setup

```
AWS_ACCESS_KEY_ID: AKIA...
AWS_SECRET_ACCESS_KEY: ...
```
Collects: IAM Policies, Security Groups, CloudTrail Logs, Config Rules

### GitHub Security Scanning

```
GITHUB_TOKEN: ghp_...
```
Collects: Repository Security, Branch Protection, Code Scanning, Secret Scanning

### Full Identity Provider Setup

```
OKTA_DOMAIN: company.okta.com
OKTA_API_TOKEN: ...
```
Collects: User Directory, MFA Policies, SSO Configuration, Access Logs

### AI-Powered Analysis

```
OPENAI_API_KEY: sk-...
# OR
ANTHROPIC_API_KEY: sk-ant-...
```
Provides: Risk Analysis, Policy Drafting, Control Recommendations

## Troubleshooting

### Server Won't Connect

1. Check that all **required** credentials are provided
2. Verify credentials are valid (not expired)
3. Ensure network access to external services
4. Check server logs for specific errors

### Missing Evidence Types

- Verify the integration credentials are configured
- Check that the external service API is accessible
- Review server capabilities in the details modal

### "Disconnected" Status

- Click the **Play** button to reconnect
- Check for error messages in server details
- Verify credentials haven't been revoked

## Best Practices

1. **Start small**: Configure one integration at a time
2. **Use service accounts**: Create dedicated API keys for GRC collection
3. **Principle of least privilege**: Grant only necessary permissions
4. **Rotate credentials**: Update API keys periodically
5. **Monitor status**: Check server health regularly

## Getting Help

- **Help Center**: Click the help icon in the top bar
- **Documentation**: `/docs/security/mcp-credential-security.md`
- **Support**: support@example.com




