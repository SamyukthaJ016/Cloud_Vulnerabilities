# Supabase + Vercel Migration Guide

This guide covers migrating GigaChad GRC from the Docker-based microservices architecture to Supabase (database/storage) + Vercel (frontend/serverless API) with Okta SSO authentication.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Supabase Setup](#supabase-setup)
4. [Okta Configuration](#okta-configuration)
5. [Vercel Deployment](#vercel-deployment)
6. [Environment Variables](#environment-variables)
7. [Database Migration](#database-migration)
8. [Storage Migration](#storage-migration)
9. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Previous Architecture (Docker)
- 6 NestJS microservices (controls, frameworks, policies, tprm, trust, audit)
- PostgreSQL database
- Redis for caching
- RustFS for file storage (S3-compatible)
- Keycloak for authentication
- Traefik for API gateway
- Docker Compose orchestration

### New Architecture (Supabase + Vercel)
- Vercel: React frontend + Serverless API functions
- Supabase: PostgreSQL database + File storage
- Okta: Direct OIDC authentication (no middleware)
- No Redis required (Vercel Edge caching available if needed)

### Cost Comparison

| Component | Docker (Self-Hosted) | Supabase + Vercel |
|-----------|---------------------|-------------------|
| Compute | $50-200/mo (cloud VMs) | $20/mo (Vercel Pro) |
| Database | Included in VM | $25/mo (Supabase Pro) |
| Storage | Included (RustFS) | Included (Supabase) |
| Auth | Included (Keycloak) | $0 (Okta existing) |
| **Total** | **$50-200/mo + maintenance** | **~$45/mo** |

---

## Prerequisites

Before starting the migration, ensure you have:

- [ ] Node.js 18+ installed
- [ ] npm or yarn package manager
- [ ] Vercel CLI (`npm i -g vercel`)
- [ ] Okta developer/enterprise account
- [ ] Supabase account (free tier works for testing)
- [ ] Git repository access

---

## Supabase Setup

### 1. Create a Supabase Project

1. Go to [supabase.com](https://supabase.com) and sign in
2. Click "New Project"
3. Choose your organization
4. Enter project details:
   - **Name**: `gigachad-grc`
   - **Database Password**: Generate a strong password (save this!)
   - **Region**: Choose closest to your users
5. Click "Create new project"

### 2. Get Database Connection Strings

After project creation, go to **Settings > Database**:

1. **Connection Pooling (for queries)**:
   - Find "Connection string" under "Connection pooling"
   - Copy the URI (uses port 6543)
   - Format: `postgres://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres`

2. **Direct Connection (for migrations)**:
   - Find "Connection string" under "Direct connection"
   - Copy the URI (uses port 5432)
   - Format: `postgres://postgres:[password]@db.[project-ref].supabase.co:5432/postgres`

### 3. Create Storage Buckets

Go to **Storage** in Supabase dashboard:

1. Click "New bucket" and create these buckets:
   - `evidence` - For evidence files (private)
   - `policies` - For policy documents (private)
   - `integrations` - For integration configs (private)
   - `questionnaires` - For questionnaire attachments (private)
   - `trust-center` - For public trust center assets (public)

2. For each private bucket, set appropriate RLS policies:

```sql
-- Example policy for evidence bucket
CREATE POLICY "Users can access their org's evidence"
ON storage.objects FOR ALL
USING (
  bucket_id = 'evidence' AND
  (storage.foldername(name))[1] = auth.jwt()->>'organization_id'
);
```

### 4. Get API Keys

Go to **Settings > API**:

- **Project URL**: `https://[project-ref].supabase.co`
- **anon/public key**: For client-side operations
- **service_role key**: For server-side operations (keep secret!)

---

## Okta Configuration

### 1. Create an OIDC Application

1. Log into your Okta Admin Console
2. Go to **Applications > Applications**
3. Click "Create App Integration"
4. Select:
   - **Sign-in method**: OIDC - OpenID Connect
   - **Application type**: Single-Page Application
5. Click "Next"

### 2. Configure the Application

**General Settings**:
- **App integration name**: `GigaChad GRC`
- **Grant type**: Authorization Code (with PKCE)

**Sign-in redirect URIs**:
```
http://localhost:5173/login/callback  (development)
https://your-app.vercel.app/login/callback  (production)
```

**Sign-out redirect URIs**:
```
http://localhost:5173  (development)
https://your-app.vercel.app  (production)
```

**Trusted Origins** (under Security > API):
```
http://localhost:5173
https://your-app.vercel.app
```

### 3. Configure User Groups for Roles

Create groups in Okta that map to GRC roles:
- `admin` - Full access
- `compliance_manager` - Manage controls, policies, evidence
- `auditor` - View access for audits
- `viewer` - Read-only access

### 4. Add Groups Claim to Tokens

1. Go to **Security > API > Authorization Servers**
2. Select your authorization server (or `default`)
3. Go to **Claims** tab
4. Click "Add Claim":
   - **Name**: `groups`
   - **Include in token type**: ID Token, Always
   - **Value type**: Groups
   - **Filter**: Matches regex `.*`

### 5. (Optional) Add Organization Claim

If you support multiple organizations:

1. Create a custom user attribute `organization_id`
2. Add a claim:
   - **Name**: `organization_id`
   - **Include in token type**: ID Token, Always
   - **Value type**: Expression
   - **Value**: `user.organization_id`

### 6. Note Your Configuration

Save these values:
- **Issuer URI**: `https://your-domain.okta.com/oauth2/default`
- **Client ID**: Found in application settings

---

## Vercel Deployment

### 1. Install Vercel CLI

```bash
npm install -g vercel
```

### 2. Link Your Project

```bash
cd gigachad-grc
vercel link
```

Follow the prompts to link to your Vercel account.

### 3. Configure Environment Variables

In Vercel Dashboard (**Settings > Environment Variables**), add:

```
# Okta (Client-side - prefix with VITE_)
VITE_OKTA_ISSUER=https://your-domain.okta.com/oauth2/default
VITE_OKTA_CLIENT_ID=your-client-id

# Okta (Server-side)
OKTA_ISSUER=https://your-domain.okta.com/oauth2/default
OKTA_CLIENT_ID=your-client-id
OKTA_AUDIENCE=api://default

# Supabase Database
DATABASE_URL=postgres://postgres.[ref]:[password]@aws-0-region.pooler.supabase.com:6543/postgres
DIRECT_URL=postgres://postgres:[password]@db.[ref].supabase.co:5432/postgres

# Supabase Storage & API
SUPABASE_URL=https://[ref].supabase.co
SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_KEY=eyJ...

# Encryption (generate with: openssl rand -hex 32)
ENCRYPTION_KEY=your-32-byte-hex-key
```

### 4. Deploy

```bash
# Production deployment
vercel --prod

# Preview deployment (for testing)
vercel
```

### 5. Configure Custom Domain (Optional)

1. Go to **Settings > Domains** in Vercel
2. Add your custom domain
3. Configure DNS as instructed
4. Update Okta redirect URIs to use custom domain

---

## Environment Variables

### Complete Environment Variable Reference

| Variable | Where Used | Required | Description |
|----------|------------|----------|-------------|
| `VITE_OKTA_ISSUER` | Frontend | Yes | Okta authorization server URL |
| `VITE_OKTA_CLIENT_ID` | Frontend | Yes | Okta application client ID |
| `OKTA_ISSUER` | API | Yes | Okta authorization server URL |
| `OKTA_CLIENT_ID` | API | Yes | Okta application client ID |
| `OKTA_AUDIENCE` | API | No | JWT audience claim (default: `api://default`) |
| `DATABASE_URL` | API | Yes | Pooled Supabase connection string |
| `DIRECT_URL` | Migrations | Yes | Direct Supabase connection string |
| `SUPABASE_URL` | API | Yes | Supabase project URL |
| `SUPABASE_ANON_KEY` | API | Yes | Supabase anonymous key |
| `SUPABASE_SERVICE_KEY` | API | Yes | Supabase service role key |
| `ENCRYPTION_KEY` | API | Yes | 32-byte hex key for encrypting sensitive data |

### Generate Encryption Key

```bash
# macOS/Linux
openssl rand -hex 32

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## Database Migration

### 1. Export Existing Data (if migrating from Docker)

```bash
# From Docker PostgreSQL
docker exec -it gigachad-grc-postgres pg_dump -U postgres gigachad_grc > backup.sql
```

### 2. Run Prisma Migrations

```bash
cd frontend

# Generate Prisma client
npx prisma generate

# Push schema to Supabase
npx prisma db push

# Or use migrations for production
npx prisma migrate deploy
```

### 3. Import Existing Data (if applicable)

```bash
# Using psql with Supabase direct connection
psql "postgres://postgres:[password]@db.[ref].supabase.co:5432/postgres" < backup.sql
```

### 4. Verify Migration

```bash
# Open Prisma Studio to inspect data
npx prisma studio
```

---

## Storage Migration

### 1. Export Files from RustFS

If you have existing files in RustFS:

```bash
# Using docker cp or S3 tools
docker cp grc-rustfs:/data/evidence ./evidence-backup/
docker cp grc-rustfs:/data/policies ./policies-backup/

# Or with AWS CLI
aws --endpoint-url http://localhost:9000 s3 sync s3://evidence ./evidence-backup/
```

### 2. Upload to Supabase Storage

Use the Supabase dashboard or CLI to upload files:

```javascript
// Script to migrate files
import { createClient } from '@supabase/supabase-js';
import fs from 'fs';
import path from 'path';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

async function migrateFiles(localDir, bucket) {
  const files = fs.readdirSync(localDir);
  
  for (const file of files) {
    const filePath = path.join(localDir, file);
    const fileContent = fs.readFileSync(filePath);
    
    await supabase.storage
      .from(bucket)
      .upload(file, fileContent);
    
    console.log(`Uploaded: ${file}`);
  }
}

// Run migration
migrateFiles('./evidence-backup', 'evidence');
migrateFiles('./policies-backup', 'policies');
```

---

## Troubleshooting

### Common Issues

#### 1. "Invalid token" errors

**Cause**: Okta configuration mismatch

**Solution**:
- Verify `OKTA_ISSUER` matches your authorization server
- Ensure `OKTA_CLIENT_ID` is correct
- Check that redirect URIs are configured in Okta

#### 2. Database connection timeouts

**Cause**: Using direct connection for queries

**Solution**:
- Use `DATABASE_URL` (pooled, port 6543) for application queries
- Use `DIRECT_URL` (direct, port 5432) only for migrations

#### 3. "Bucket not found" storage errors

**Cause**: Storage bucket not created or wrong name

**Solution**:
- Create buckets in Supabase dashboard
- Ensure bucket names match: `evidence`, `policies`, `integrations`, `questionnaires`, `trust-center`

#### 4. CORS errors

**Cause**: Missing CORS configuration

**Solution**:
- CORS is configured in `vercel.json`
- Ensure your domain is in Okta's Trusted Origins

#### 5. Cold start latency

**Cause**: Serverless function initialization

**Solution**:
- Prisma client is cached globally to reduce cold starts
- Consider Vercel's Edge Functions for frequently accessed endpoints
- Enable Vercel's Edge caching for static data

### Debug Mode

Enable detailed logging in development:

```typescript
// In API routes
if (process.env.NODE_ENV === 'development') {
  console.log('Request:', req.method, req.url);
  console.log('User:', req.user);
}
```

### Getting Help

- [Supabase Documentation](https://supabase.com/docs)
- [Vercel Documentation](https://vercel.com/docs)
- [Okta Developer Documentation](https://developer.okta.com/docs/)
- [Prisma Documentation](https://www.prisma.io/docs)

---

## Rollback Procedure

If you need to rollback to the Docker architecture:

1. Update DNS to point to your Docker host
2. Restore database from backup
3. Start Docker services: `docker-compose up -d`
4. Update frontend `.env` to use legacy API endpoints

---

## Security Considerations

1. **Secrets Management**: Never commit secrets to Git. Use Vercel environment variables.

2. **Database Access**: Supabase uses Row Level Security (RLS). Ensure policies are configured.

3. **API Authentication**: All API routes use JWT validation via Okta.

4. **Storage Security**: Use signed URLs for private file access.

5. **Encryption**: Sensitive integration credentials are encrypted with AES-256-GCM.

---

*Last Updated: December 2025*
