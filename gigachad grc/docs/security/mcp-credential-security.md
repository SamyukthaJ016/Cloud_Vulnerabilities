# MCP Server Credential Security

## Overview

This document describes the security architecture for storing and managing credentials used by Model Context Protocol (MCP) servers in GigaChad GRC. MCP servers connect to external services (AWS, Azure, GitHub, Okta, etc.) to collect compliance evidence, and these connections require sensitive API credentials.

## Security Architecture

### Encryption Standard

All MCP server credentials are encrypted using **AES-256-GCM** (Advanced Encryption Standard with Galois/Counter Mode), which provides:

- **256-bit encryption**: Military-grade encryption strength
- **Authenticated encryption**: Ensures data integrity and authenticity
- **IV (Initialization Vector)**: Unique 16-byte random IV per encryption operation
- **Auth Tag**: 16-byte authentication tag to detect tampering

### Data Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CREDENTIAL LIFECYCLE                          │
└──────────────────────────────────────────────────────────────────────┘

1. USER INPUT                    2. ENCRYPTION                    3. STORAGE
┌─────────────┐                 ┌─────────────┐                 ┌─────────────┐
│ API Key     │ ──────────────► │ AES-256-GCM │ ──────────────► │ PostgreSQL  │
│ Secret      │    plaintext    │ Encryption  │    encrypted    │ Database    │
│ Token       │                 │             │                 │             │
└─────────────┘                 └─────────────┘                 └─────────────┘
                                       │
                                       │ encryption key
                                       │ (from env var)
                                       ▼
                                ┌─────────────┐
                                │ SCRYPT KDF  │
                                │ (key derive)│
                                └─────────────┘

4. RETRIEVAL                    5. DECRYPTION                    6. USAGE
┌─────────────┐                 ┌─────────────┐                 ┌─────────────┐
│ PostgreSQL  │ ──────────────► │ AES-256-GCM │ ──────────────► │ MCP Server  │
│ Database    │    encrypted    │ Decryption  │    plaintext    │ Process     │
│             │                 │             │    (memory)     │             │
└─────────────┘                 └─────────────┘                 └─────────────┘
                                                                       │
                                                                       ▼
                                                                ┌─────────────┐
                                                                │ External    │
                                                                │ Service API │
                                                                │ (AWS, etc.) │
                                                                └─────────────┘
```

### Storage Structure

Credentials are stored in the `mcp_credentials` table:

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT | Unique identifier (UUID) |
| `server_id` | TEXT | MCP server instance ID |
| `template_id` | TEXT | Template type (e.g., `grc-evidence`) |
| `server_name` | TEXT | Human-readable server name |
| `encrypted_env` | TEXT | JSON object containing IV, encrypted data, and auth tag |
| `configured_integrations` | JSONB | List of configured integration names |
| `created_at` | TIMESTAMP | Creation timestamp |
| `created_by` | TEXT | User who created the configuration |
| `last_updated` | TIMESTAMP | Last modification timestamp |

### Encrypted Data Format

```json
{
  "iv": "a1b2c3d4e5f6g7h8i9j0k1l2",
  "encrypted": "encrypted_hex_string...",
  "authTag": "authentication_tag_hex"
}
```

## Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `MCP_ENCRYPTION_KEY` | Recommended | Primary encryption key for MCP credentials | `your-64-char-random-string` |
| `ENCRYPTION_KEY` | Fallback | General encryption key (used if MCP key not set) | `your-64-char-random-string` |

### Generating a Secure Key

```bash
# Generate a cryptographically secure 64-character key
openssl rand -hex 32

# Or using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Example output: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
```

### Setting the Key

**Docker Compose:**
```yaml
services:
  controls:
    environment:
      - MCP_ENCRYPTION_KEY=${MCP_ENCRYPTION_KEY}
```

**Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mcp-secrets
type: Opaque
data:
  MCP_ENCRYPTION_KEY: <base64-encoded-key>
```

**.env file (development only):**
```env
MCP_ENCRYPTION_KEY=your-64-char-random-string-here
```

> ⚠️ **Warning**: Never commit encryption keys to version control.

## API Reference

### Deploy MCP Server with Credentials

**Endpoint:** `POST /api/mcp/templates/:templateId/deploy`

**Request:**
```json
{
  "env": {
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  },
  "userId": "admin@company.com",
  "autoConnect": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "grc-evidence-1765222822161",
    "name": "GRC Evidence Collection Server",
    "status": "disconnected",
    "templateId": "grc-evidence",
    "createdAt": "2025-12-08T19:40:22.162Z",
    "createdBy": "admin@company.com",
    "configuration": {
      "configuredIntegrations": ["AWS", "GitHub"],
      "evidenceTypes": ["AWS IAM Policies", "Repository Security", "..."]
    }
  }
}
```

### Get Masked Credentials (Audit)

**Endpoint:** `GET /api/mcp/servers/:serverId/credentials`

**Response:**
```json
{
  "success": true,
  "data": {
    "serverId": "grc-evidence-1765222822161",
    "credentials": {
      "AWS_ACCESS_KEY_ID": "AKIA••••MPLE",
      "AWS_SECRET_ACCESS_KEY": "wJal••••EKEY",
      "GITHUB_TOKEN": "ghp_••••xxxx"
    },
    "note": "Credentials are masked for security. Full values are never exposed via API."
  }
}
```

### Validate Credentials

**Endpoint:** `POST /api/mcp/servers/:serverId/credentials/validate`

**Request:**
```json
{
  "requiredKeys": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "valid": true,
    "missing": []
  }
}
```

## Security Controls

### What's Protected

| Control | Implementation |
|---------|----------------|
| Encryption at Rest | AES-256-GCM encryption in database |
| Encryption in Transit | HTTPS for all API calls |
| Key Derivation | SCRYPT with salt for key stretching |
| Authentication Tags | GCM auth tags prevent tampering |
| Unique IVs | Random 16-byte IV per encryption |
| Masked Display | Only first/last 4 characters shown |
| Audit Logging | Creator, timestamp, modifications tracked |

### What's NOT Exposed

- ❌ Full credential values are never returned by any API
- ❌ Encryption keys are never logged or exposed
- ❌ Decrypted credentials are never persisted to disk
- ❌ Database queries never return unencrypted values

### Memory Handling

- Decrypted credentials are held in memory only during active use
- Cache is cleared when service restarts
- No swap file persistence of secrets

## Audit & Compliance

### Audit Trail

Every MCP server configuration records:

| Field | Purpose |
|-------|---------|
| `created_by` | Who created the configuration |
| `created_at` | When it was created |
| `last_updated` | When it was last modified |
| `configured_integrations` | Which integrations have credentials |

### Compliance Mappings

| Framework | Control | How Addressed |
|-----------|---------|---------------|
| SOC 2 | CC6.1 - Logical Access | Encrypted credential storage |
| SOC 2 | CC6.7 - Encryption | AES-256-GCM encryption |
| ISO 27001 | A.10.1.1 - Cryptographic Controls | Industry-standard encryption |
| ISO 27001 | A.12.3.1 - Information Backup | Encrypted backups |
| NIST 800-53 | SC-13 - Cryptographic Protection | FIPS-compliant algorithm |
| PCI DSS | Req 3.4 - Render PAN Unreadable | Strong encryption |

## Recommendations

### 🔴 Critical (Must Do)

1. **Generate a unique encryption key for production**
   ```bash
   # Generate and set immediately
   export MCP_ENCRYPTION_KEY=$(openssl rand -hex 32)
   ```

2. **Store encryption keys in a secrets manager**
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault
   - Google Secret Manager

3. **Never use the default encryption key in production**
   - The default key logs a warning at startup
   - It provides no real security

4. **Enable TLS/HTTPS for all API endpoints**
   - Credentials are encrypted at rest, but need protection in transit

### 🟡 Important (Should Do)

5. **Implement key rotation**
   - Rotate encryption keys annually or after suspected compromise
   - Use the `rotateEncryptionKey()` method (implementation guide below)

6. **Enable database encryption**
   - Use PostgreSQL's native encryption (pgcrypto) as an additional layer
   - Enable Transparent Data Encryption (TDE) if available

7. **Set up monitoring and alerting**
   - Monitor failed decryption attempts
   - Alert on unusual credential access patterns
   - Track credential validation failures

8. **Implement rate limiting**
   - Limit credential retrieval API calls
   - Prevent brute-force attacks on encrypted data

### 🟢 Nice to Have (Consider)

9. **Hardware Security Modules (HSM)**
   - Use HSM for key storage in high-security environments
   - AWS CloudHSM or Azure Dedicated HSM

10. **Multi-tenant key isolation**
    - Use separate encryption keys per organization
    - Prevents cross-tenant credential exposure

11. **Credential expiration**
    - Implement automatic credential rotation reminders
    - Track credential age and alert when approaching expiration

## Key Rotation Guide

### Manual Key Rotation Process

```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -hex 32)

# 2. Set both old and new keys temporarily
export MCP_ENCRYPTION_KEY_OLD=$MCP_ENCRYPTION_KEY
export MCP_ENCRYPTION_KEY=$NEW_KEY

# 3. Run rotation script (re-encrypts all credentials)
# This needs to be implemented in the service

# 4. Verify all credentials decryptable with new key

# 5. Remove old key from environment
unset MCP_ENCRYPTION_KEY_OLD
```

### Automated Rotation (Future)

```typescript
// Service method (to be implemented)
await credentialsService.rotateEncryptionKey(newKey);
```

## Troubleshooting

### Common Issues

**"Failed to decrypt credentials"**
- Cause: Encryption key mismatch
- Solution: Verify `MCP_ENCRYPTION_KEY` matches the key used for encryption

**"Using default encryption key" warning**
- Cause: No encryption key configured
- Solution: Set `MCP_ENCRYPTION_KEY` environment variable

**Credentials not persisting after restart**
- Cause: Database connection issue or table missing
- Solution: Run migration: `npx prisma db execute --file migrations/20251208_mcp_credentials/migration.sql`

**"Credential validation failed"**
- Cause: Required credentials not configured
- Solution: Re-deploy server with all required credentials

### Debug Logging

Enable debug logging for credential operations:

```bash
export DEBUG=prisma:client:request_handler
export LOG_LEVEL=debug
```

## Security Incident Response

### If Encryption Key is Compromised

1. **Immediately** generate a new encryption key
2. **Rotate all MCP server credentials** using external providers
3. **Re-encrypt** all stored credentials with new key
4. **Audit** access logs for unauthorized access
5. **Notify** affected parties per your incident response plan

### If Database is Breached

1. Encrypted credentials remain protected (AES-256 requires key to decrypt)
2. **Still rotate** all credentials as a precaution
3. **Rotate** the encryption key
4. **Investigate** how breach occurred

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-12-08 | Initial implementation with AES-256-GCM |

## Related Documentation

- [MCP Server Management](/docs/mcp/mcp-server-management.md)
- [Integration Security](/docs/security/integration-security.md)
- [Encryption Key Management](/docs/security/encryption-keys.md)
- [Audit Logging](/docs/audit/audit-logging.md)




