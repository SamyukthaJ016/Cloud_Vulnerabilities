# Remote / Non-Localhost Deployment Guide

This guide covers deploying GigaChad GRC on a remote server, a VM, or a machine on your local network where users access it via IP address or hostname instead of `localhost`.

## Overview

When running GigaChad GRC on a remote machine, three things change compared to localhost:

1. **CORS** -- The browser's origin (`http://192.168.1.50:3000`) must be allowed by backend services
2. **Keycloak redirect URIs** -- Keycloak must know the correct frontend URL for OAuth callbacks
3. **Frontend API URL** -- The frontend must know where to send API requests

If any of these are misconfigured, you will see one of:

- Keycloak redirect loop (page loads briefly then redirects to `localhost:8080/realms/...`)
- CORS errors in the browser console (`Access-Control-Allow-Origin` missing)
- API requests failing with `Failed to fetch`

## Step 1: Determine Your Access URL

Decide how users will access the platform:

| Scenario      | Example URL                | Notes                            |
| ------------- | -------------------------- | -------------------------------- |
| Same machine  | `http://localhost:3000`    | Default, no changes needed       |
| LAN IP        | `http://192.168.1.50:3000` | Other machines on same network   |
| Hostname      | `http://grc.internal:3000` | Requires DNS or `/etc/hosts`     |
| Public domain | `https://grc.example.com`  | Requires DNS, reverse proxy, TLS |

## Step 2: Configure Environment Variables

### `.env` file changes

```bash
# Replace YOUR_HOST with your IP or hostname
# Examples: 192.168.1.50, grc.internal, grc.example.com

# CORS: Allow the browser origin
CORS_ORIGINS=http://YOUR_HOST:3000,http://localhost:3000

# Frontend: Tell the frontend where the API is
# Leave blank if using Traefik (requests go through same origin)
VITE_API_URL=

# Keycloak: Set the frontend URL for OAuth redirects
KEYCLOAK_FRONTEND_URL=http://YOUR_HOST:8080

# Dev Auth: Enable for local/demo use (skip Keycloak entirely)
VITE_ENABLE_DEV_AUTH=true
USE_DEV_AUTH=true
```

### Using Dev Auth (recommended for non-production)

The simplest approach for demo or development on a remote machine is to use Dev Auth mode, which bypasses Keycloak entirely:

1. Set `VITE_ENABLE_DEV_AUTH=true` and `USE_DEV_AUTH=true` in `.env`
2. Rebuild the frontend: `docker compose up -d --build frontend`
3. Access the platform and click "Dev Login"

This avoids all Keycloak redirect URI and HTTPS configuration.

### Using Keycloak (production)

If you need Keycloak SSO for production use:

1. Set up TLS/HTTPS (Keycloak requires HTTPS in production mode)
2. Configure Keycloak realm redirect URIs (see Step 3)
3. Set `VITE_ENABLE_DEV_AUTH=false` and `USE_DEV_AUTH=false`

## Step 3: Configure Keycloak Redirect URIs

If using Keycloak (not Dev Auth), you must update the allowed redirect URIs.

### Option A: Edit the realm export before first start

Edit `auth/realm-export.json` and find the `grc-frontend` client. Update `redirectUris` and `webOrigins`:

```json
{
  "clientId": "grc-frontend",
  "redirectUris": ["http://YOUR_HOST:3000/*", "http://localhost:3000/*"],
  "webOrigins": ["http://YOUR_HOST:3000", "http://localhost:3000"]
}
```

### Option B: Update via Keycloak Admin Console (after first start)

1. Open `http://YOUR_HOST:8080` (Keycloak Admin Console)
2. Log in with the credentials from your `.env` (`KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`)
3. Select the `gigachad-grc` realm
4. Go to **Clients** -> **grc-frontend**
5. Under **Settings**:
   - Add `http://YOUR_HOST:3000/*` to **Valid Redirect URIs**
   - Add `http://YOUR_HOST:3000` to **Web Origins**
6. Click **Save**

## Step 4: Configure Docker Compose for Remote Access

By default, ports bind to `127.0.0.1` (localhost only). To allow remote access, you need to bind to `0.0.0.0`.

### Override port bindings

Create a `docker-compose.override.yml`:

```yaml
services:
  frontend:
    ports:
      - '0.0.0.0:3000:80'
  keycloak:
    ports:
      - '0.0.0.0:8080:8080'
  traefik:
    ports:
      - '0.0.0.0:80:80'
      - '0.0.0.0:443:443'
```

Or modify the port bindings directly in `docker-compose.yml` by removing the `127.0.0.1:` prefix.

> **Security warning:** Binding to `0.0.0.0` exposes services to your entire network. Use firewall rules to restrict access in production.

## Step 5: Rebuild and Start

```bash
# Rebuild with new environment
docker compose up -d --build

# Verify services are accessible
curl http://YOUR_HOST:3000    # Frontend
curl http://YOUR_HOST:3001    # Controls API
```

## Firewall Configuration

If running on a cloud VM or behind a firewall, open these ports:

| Port      | Service               | Required                                                       |
| --------- | --------------------- | -------------------------------------------------------------- |
| 3000      | Frontend              | Yes                                                            |
| 80/443    | Traefik (API Gateway) | Yes (if using Traefik routing)                                 |
| 8080      | Keycloak              | Only if using Keycloak SSO                                     |
| 3001-3007 | Backend services      | Only for direct API access (Traefik handles routing otherwise) |

## Troubleshooting

### Keycloak redirects to `localhost` instead of your IP

Your Keycloak `KEYCLOAK_FRONTEND_URL` is not set or still points to localhost. Set it in `.env`:

```
KEYCLOAK_FRONTEND_URL=http://YOUR_HOST:8080
```

Then restart Keycloak: `docker compose restart keycloak`

### CORS errors in browser console

The browser origin is not in the `CORS_ORIGINS` list. Add your access URL:

```
CORS_ORIGINS=http://YOUR_HOST:3000,http://localhost:3000
```

Restart backend services: `docker compose restart controls frameworks policies tprm trust audit`

### "Failed to fetch" on API calls

The frontend cannot reach the backend API. Check:

1. Backend services are running: `docker compose ps`
2. If not using Traefik, set `VITE_API_URL=http://YOUR_HOST:3001` and rebuild the frontend
3. If using Traefik, ensure port 80 is accessible from the client machine

### Connection refused from another machine

Ports are bound to `127.0.0.1`. See Step 4 to bind to `0.0.0.0`.

### HTTPS required for production Keycloak

Keycloak production mode requires HTTPS. For local/demo use, enable Dev Auth instead. For production, see the [SSL Configuration Guide](SSL_CONFIGURATION.md) and [Production Deployment Guide](PRODUCTION_DEPLOYMENT.md).
