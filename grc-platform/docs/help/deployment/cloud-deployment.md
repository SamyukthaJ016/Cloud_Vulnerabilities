# Cloud Deployment Guide

GigaChad GRC can be deployed to the cloud using Supabase for database/storage and Vercel for hosting. This guide covers the deployment process and configuration options.

## Deployment Options

### Option 1: Supabase + Vercel (Recommended)

The recommended cloud deployment uses:

- **Vercel** for frontend hosting and serverless API functions
- **Supabase** for PostgreSQL database and file storage
- **Okta** for enterprise SSO authentication

**Estimated Cost**: ~$45/month (Vercel Pro $20 + Supabase Pro $25)

### Option 2: Docker Self-Hosted

For organizations requiring on-premise deployment, GigaChad GRC supports Docker Compose deployment. See the [Self-Hosted Deployment Guide](../../DEPLOYMENT.md).

---

## Supabase + Vercel Deployment

### Prerequisites

Before deploying, you'll need:

1. **Okta Account** - For enterprise SSO authentication
2. **Supabase Account** - Free tier available at [supabase.com](https://supabase.com)
3. **Vercel Account** - Free tier available at [vercel.com](https://vercel.com)
4. **Git Repository** - GitHub, GitLab, or Bitbucket

### Step 1: Create Supabase Project

1. Log in to [Supabase](https://supabase.com)
2. Click "New Project"
3. Configure:
   - **Project Name**: `gigachad-grc`
   - **Database Password**: Use a strong password
   - **Region**: Choose closest to your users
4. Save your database password securely

### Step 2: Get Supabase Credentials

After project creation, navigate to **Settings > API**:

- **Project URL**: `https://xxxxx.supabase.co`
- **anon/public key**: Used for client-side operations
- **service_role key**: Used for server-side operations (keep secret!)

Navigate to **Settings > Database** for connection strings:

- **Pooled Connection** (port 6543): For application queries
- **Direct Connection** (port 5432): For database migrations

### Step 3: Configure Okta

1. In Okta Admin Console, go to **Applications > Create App Integration**
2. Select **OIDC - OpenID Connect** and **Single-Page Application**
3. Configure redirect URIs:
   ```
   https://your-app.vercel.app/login/callback
   ```
4. Note your **Client ID** and **Issuer URL**

### Step 4: Deploy to Vercel

1. Import your Git repository in Vercel
2. Set environment variables (see below)
3. Deploy!

### Environment Variables

Configure these in Vercel Dashboard (**Settings > Environment Variables**):

| Variable               | Description                        |
| ---------------------- | ---------------------------------- |
| `VITE_OKTA_ISSUER`     | Your Okta authorization server URL |
| `VITE_OKTA_CLIENT_ID`  | Okta application client ID         |
| `DATABASE_URL`         | Supabase pooled connection string  |
| `DIRECT_URL`           | Supabase direct connection string  |
| `SUPABASE_URL`         | Supabase project URL               |
| `SUPABASE_ANON_KEY`    | Supabase anonymous key             |
| `SUPABASE_SERVICE_KEY` | Supabase service role key          |
| `ENCRYPTION_KEY`       | 32-byte hex key for encryption     |

### Step 5: Run Database Migrations

After first deployment:

```bash
npx prisma migrate deploy
```

---

## Storage Buckets

Create these storage buckets in Supabase:

| Bucket           | Access  | Purpose                      |
| ---------------- | ------- | ---------------------------- |
| `evidence`       | Private | Evidence files and documents |
| `policies`       | Private | Policy document storage      |
| `integrations`   | Private | Integration configuration    |
| `questionnaires` | Private | Questionnaire attachments    |
| `trust-center`   | Public  | Trust center public assets   |

---

## Custom Domain Setup

1. In Vercel, go to **Settings > Domains**
2. Add your custom domain
3. Configure DNS records as instructed
4. Update Okta redirect URIs to use custom domain

---

## Monitoring & Logs

### Vercel Logs

- Access via Vercel Dashboard > **Deployments > Logs**
- Real-time function execution logs

### Supabase Logs

- Access via Supabase Dashboard > **Logs**
- Database query logs and performance metrics

---

## Security Best Practices

1. **Enable MFA** on all admin accounts (Vercel, Supabase, Okta)
2. **Rotate keys** periodically, especially after personnel changes
3. **Use environment variables** - never commit secrets to Git
4. **Configure RLS** (Row Level Security) in Supabase
5. **Monitor access logs** for suspicious activity

---

## Scaling Considerations

### Database

- Supabase Pro supports up to 8GB database
- For larger deployments, consider Supabase Enterprise

### API

- Vercel Functions auto-scale based on traffic
- Cold starts can be mitigated with Edge Functions

### Storage

- Supabase Storage has no hard limits on Pro plan
- Consider CDN for frequently accessed files

---

## Support

For deployment assistance:

- Technical Documentation: `/docs/deployment/`
- Community Support: GitHub Discussions
- Enterprise Support: Contact your account manager

---

_Last Updated: December 2025_
