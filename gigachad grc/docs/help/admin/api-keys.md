# API Keys

Manage API keys for programmatic access to the GigaChad GRC platform.

## Overview

API Keys enable:
- Programmatic platform access
- Third-party integrations
- Automation scripts
- Custom applications

## Accessing API Keys

Navigate to **Settings → API Keys**

## API Key List

View all API keys:
- **Name**: Key identifier
- **Created**: Creation date
- **Last Used**: Most recent use
- **Status**: Active/Revoked
- **Permissions**: Access scope

## Creating API Keys

### Create New Key
1. Click **Create API Key**
2. Enter:
   - **Name**: Descriptive name
   - **Description**: Purpose of key
3. Select permissions:
   - Read-only access
   - Full access
   - Custom scope
4. Set expiration (optional):
   - Never expire
   - 30 days
   - 90 days
   - Custom date
5. Click **Create**

### Key Display
**Important**: The key is shown only once!
1. Copy the key immediately
2. Store securely
3. Cannot be retrieved later

## API Key Permissions

### Permission Scopes

| Scope | Description |
|-------|-------------|
| **read:all** | Read access to all data |
| **write:all** | Read and write access |
| **controls:read** | Read controls only |
| **controls:write** | Manage controls |
| **risks:read** | Read risks only |
| **risks:write** | Manage risks |
| **evidence:read** | Read evidence |
| **evidence:write** | Upload/manage evidence |

### Custom Scopes
Create specific permissions:
1. Choose **Custom Scope**
2. Select individual permissions
3. Combine as needed

## Managing Keys

### View Key Details
Click any key to see:
- Creation date
- Last used
- Usage statistics
- Permissions

### Revoke Key
1. Click key menu (⋮)
2. Select **Revoke**
3. Confirm revocation

Revoked keys:
- Cannot be used
- Cannot be restored
- Remain in history

### Regenerate Key
If key is compromised:
1. Revoke old key
2. Create new key
3. Update applications

## Using API Keys

### Authentication
Include in request header:
```
Authorization: Bearer YOUR_API_KEY
```

### Example Request
```bash
curl -X GET \
  https://api.yourdomain.com/api/controls \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Rate Limiting
API requests are limited:
- 1000 requests per hour (default)
- Contact admin for higher limits

## Security Best Practices

### Key Storage
- Never commit to version control
- Use environment variables
- Encrypt at rest
- Limit access to keys

### Key Rotation
- Rotate keys regularly
- Create new before revoking old
- Update all integrations
- Document rotation

### Least Privilege
- Minimum necessary permissions
- Separate keys per integration
- Time-limited when possible

### Monitoring
- Review usage regularly
- Alert on unusual patterns
- Audit key access
- Investigate anomalies

## Troubleshooting

### Authentication Failed
1. Verify key is correct
2. Check key is not revoked
3. Verify header format
4. Check key permissions

### Rate Limit Exceeded
1. Check request volume
2. Implement backoff
3. Request higher limit
4. Optimize API calls

### Permission Denied
1. Verify key scope
2. Check resource permissions
3. Review audit log
4. Contact admin

## API Documentation

Full API reference available:
- [API Reference](/docs/API.md)
- OpenAPI/Swagger documentation
- Code examples

## Related Topics

- [Permission Groups](permissions.md)
- [Organization Settings](organization.md)
- [Audit Logs](audit-logs.md)

