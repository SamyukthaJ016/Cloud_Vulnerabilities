# System Health & Production Readiness

The GigaChad GRC platform includes comprehensive system health monitoring and production readiness checks to ensure your deployment is secure and resilient.

## Overview

System health features are accessible to administrators in **Settings > Organization Settings**, at the bottom of the page under "System Health."

## System Health Banner

The System Health Banner displays critical warnings at the top of the admin dashboard. It automatically checks for:

### Security Issues
- **Development Authentication in Production**: Critical alert if using DevAuthGuard in production
- **Default Passwords**: Warning if PostgreSQL, Redis, or RustFS are using default passwords
- **Missing Encryption Key**: Alert if ENCRYPTION_KEY is not set or too short
- **Missing JWT Secret**: Warning if JWT_SECRET is not properly configured

### Backup Configuration
- **Remote Backup Status**: Warning if DR_REMOTE_BACKUP_ENABLED is not true in production
- **Backup Retention**: Alert if retention is less than 7 days

### Database Security
- **SSL Connections**: Warning if database connections aren't using SSL in production
- **Connection Pool Status**: Health monitoring of database connections

### Storage Security
- **Object Storage SSL**: Warning if RustFS/S3 connections aren't encrypted

## Production Readiness Score

The Production Readiness widget provides a 0-100 score indicating how prepared your instance is for production deployment.

### Score Interpretation
- **80-100 (Green)**: Production ready
- **60-79 (Yellow)**: Some warnings to address
- **0-59 (Red)**: Critical issues must be resolved

### Categories Checked
1. **Security Configuration**
2. **Backup Configuration**
3. **Database Configuration**
4. **Authentication Setup**
5. **Network/CORS Settings**
6. **Monitoring Configuration**

## Setup Wizard

For new installations, the Setup Wizard guides administrators through essential configuration steps:

1. **Database Connection** - Verify PostgreSQL is accessible
2. **Encryption Key** - Generate and configure encryption
3. **Admin User** - Create initial administrator account
4. **Organization** - Set up default organization
5. **Authentication** - Configure Keycloak SSO
6. **Backup Configuration** - Enable remote backup for disaster recovery

The wizard can be accessed at any time from Settings to review configuration status.

## CLI Validation Script

For CI/CD pipelines and deployment automation, use the validation script:

```bash
# Basic validation
npm run validate:production

# Strict mode (fail on warnings)
npm run validate:production:strict
```

### Exit Codes
- **0**: All checks passed
- **1**: Critical errors found (blocks deployment)
- **2**: Warnings found (only in strict mode)

### Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║         GigaChad GRC Production Validation                    ║
╚═══════════════════════════════════════════════════════════════╝

━━━ Security Configuration ━━━
✓ ENCRYPTION_KEY is properly configured
✓ JWT_SECRET is properly configured
✓ All passwords have been changed from defaults

━━━ Backup Configuration ━━━
✓ Backup script exists
✓ Remote backup is enabled
✓ Backup retention is 30 days

━━━ Summary ━━━
  Passed:   12
  Warnings: 2
  Errors:   0

  Production Readiness Score: 92/100

✅ Validation PASSED - System is production ready!
```

## Docker Entrypoint Features

When running in Docker, the entrypoint script automatically:

1. **Waits for Dependencies** - Ensures PostgreSQL and Redis are ready
2. **Runs Migrations** - Applies pending database migrations
3. **Schedules Backups** - Sets up cron job if AUTO_BACKUP_ENABLED=true
4. **Checks Configuration** - Logs warnings for production misconfigurations

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| AUTO_BACKUP_ENABLED | false | Enable automatic backup scheduling |
| AUTO_BACKUP_SCHEDULE | 0 2 * * * | Cron schedule (default: 2 AM daily) |
| AUTO_MIGRATE | true | Run database migrations on startup |
| WAIT_FOR_DB | true | Wait for PostgreSQL before starting |
| DB_WAIT_TIMEOUT | 60 | Seconds to wait for database |

## API Endpoints

### GET /api/system/health
Basic health check (no authentication required).

### GET /api/system/health/detailed
Comprehensive health check with all system checks (admin only).

### GET /api/system/warnings
Active warnings for dashboard display (admin only).

### GET /api/system/production-readiness
Production readiness score and recommendations (admin only).

### GET /api/system/setup/status
Setup wizard progress status (admin only).

### GET /api/system/backup/status
Backup configuration status (admin only).

## Best Practices

1. **Run validation before every deployment**
   ```bash
   npm run validate:production:strict
   ```

2. **Address all critical issues immediately**
   - Never deploy with ERRORS in the validation output
   - Review warnings and create tickets to address them

3. **Enable automatic backups in production**
   ```bash
   AUTO_BACKUP_ENABLED=true
   DR_REMOTE_BACKUP_ENABLED=true
   DR_REMOTE_BACKUP_S3_BUCKET=your-backup-bucket
   ```

4. **Monitor the health banner daily**
   - Check for new warnings after configuration changes
   - Don't dismiss critical warnings without resolution

5. **Test disaster recovery regularly**
   - Run the restore script in a staging environment
   - Verify backup integrity monthly

## Troubleshooting

### "ENCRYPTION_KEY is not set"
Generate a secure key:
```bash
openssl rand -hex 32
```
Add to your `.env.prod` file.

### "Using development authentication in production"
Ensure:
- `USE_DEV_AUTH=false` or unset
- `KEYCLOAK_URL` is configured
- `KEYCLOAK_REALM` and `KEYCLOAK_CLIENT_ID` are set

### "Remote backup is not configured"
Configure S3/RustFS for offsite backups:
```bash
DR_REMOTE_BACKUP_ENABLED=true
DR_REMOTE_BACKUP_S3_BUCKET=my-backup-bucket
DR_REMOTE_BACKUP_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
```

### "Database SSL is not enabled"
Add SSL to your DATABASE_URL:
```
postgresql://user:pass@host:5432/db?sslmode=require
```

