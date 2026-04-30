# Upgrade Guide

This guide covers upgrading GigaChad GRC between versions.

## Before You Upgrade

### 1. Create a Backup

**Always backup before upgrading:**

```bash
# Using the backup script
./deploy/backup.sh

# Or manually
docker exec grc-postgres pg_dump -U grc_user gigachad_grc > backup_$(date +%Y%m%d).sql
```

### 2. Review Release Notes

Check the [CHANGELOG.md](../CHANGELOG.md) for:
- Breaking changes
- Required migration steps
- New environment variables
- Deprecated features

### 3. Test in Staging First

If possible, test the upgrade in a staging environment before production.

---

## Standard Upgrade Process

### Docker Compose Deployment

```bash
# 1. Pull the latest code
git pull origin main

# 2. Stop services
docker compose down

# 3. Pull new images (if using pre-built)
docker compose pull

# 4. Rebuild local images
docker compose build

# 5. Run database migrations
docker compose run --rm controls npx prisma migrate deploy

# 6. Start services
docker compose up -d

# 7. Verify health
docker compose ps
curl http://localhost:3001/health
```

### Local Development

```bash
# 1. Pull the latest code
git pull origin main

# 2. Update dependencies
npm install

# 3. Update service dependencies
cd services/controls && npm install && npx prisma migrate deploy
cd ../frameworks && npm install && npx prisma migrate deploy
cd ../policies && npm install && npx prisma migrate deploy
cd ../tprm && npm install && npx prisma migrate deploy
cd ../trust && npm install && npx prisma migrate deploy
cd ../audit && npm install && npx prisma migrate deploy

# 4. Update frontend
cd frontend && npm install

# 5. Restart services
```

---

## Version-Specific Upgrade Notes

### Upgrading to v1.0.0-beta (Initial Release)

This is the initial public release. If you're installing fresh, see [QUICK_START.md](./QUICK_START.md).

**Key Changes:**
- Migrated from `xlsx` to `exceljs` for Excel import/export
- Upgraded `@nestjs/cli` to v11.x across all services
- CI/CD pipeline with GitHub Actions

**Required Actions:**
1. If you have custom Excel import/export code, update to use `exceljs` API
2. Run `npm install` to get the new dependencies

---

## Database Migrations

### Running Migrations

Migrations are handled by Prisma. To apply pending migrations:

```bash
# From each service directory
cd services/controls
npx prisma migrate deploy
```

### Checking Migration Status

```bash
npx prisma migrate status
```

### Rolling Back

Prisma doesn't support automatic rollback. If needed:

1. Restore from backup
2. Or manually write a DOWN migration SQL

---

## Handling Breaking Changes

### API Changes

If the API has breaking changes:

1. Check the API docs at `/api/docs` for the new endpoints
2. Update any integrations or scripts that call the API
3. Test thoroughly before deploying to production

### Database Schema Changes

Major schema changes may require:

1. Data migration scripts (provided in `database/migrations/`)
2. Application downtime during migration
3. Review of any custom queries or reports

### Environment Variables

New features may require new environment variables:

1. Compare your `.env` with the latest `deploy/env.example`
2. Add any new required variables
3. Remove deprecated variables

---

## Rollback Procedure

If an upgrade fails:

### 1. Stop Services

```bash
docker compose down
```

### 2. Restore Code

```bash
git checkout v1.0.0-beta  # Or your previous version
```

### 3. Restore Database

```bash
# Restore from backup
docker exec -i grc-postgres psql -U grc_user -d gigachad_grc < backup_YYYYMMDD.sql
```

### 4. Restart Services

```bash
docker compose up -d
```

---

## Zero-Downtime Upgrades

For production environments requiring zero downtime:

### Blue-Green Deployment

1. Deploy new version to "green" environment
2. Run migrations on green
3. Test green environment
4. Switch traffic from "blue" to "green"
5. Keep blue as rollback option

### Rolling Updates (Kubernetes)

If using Kubernetes with our Helm chart:

```bash
helm upgrade gigachad-grc ./helm/gigachad-grc \
  --set image.tag=v1.1.0 \
  --wait
```

---

## Post-Upgrade Verification

After upgrading, verify:

1. **Services are healthy:**
   ```bash
   docker compose ps
   curl http://localhost:3001/health
   ```

2. **UI is accessible:**
   - Open http://localhost:3000
   - Log in and verify dashboard loads

3. **Key features work:**
   - Create a test control
   - Upload evidence
   - Check risk register

4. **Check logs for errors:**
   ```bash
   docker compose logs --tail=100
   ```

---

## Getting Help

If you encounter issues during upgrade:

1. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
2. Search [GitHub Issues](../../issues)
3. Open a new issue with:
   - Current version
   - Target version
   - Error messages
   - Steps to reproduce

---

*Last updated: December 2024*

