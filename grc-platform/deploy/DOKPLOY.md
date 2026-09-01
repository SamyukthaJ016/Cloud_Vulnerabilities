# GRC and Keycloak on Dokploy

Use `grc-platform/docker-compose.dokploy.yml` as a second compose application in the existing `cloudguard-poc` production environment. It does not bind host ports 80 or 443; Dokploy remains the only public reverse proxy.

## Compose Settings

- Repository: the same CloudGuard Git repository and deployment branch
- Compose path: `grc-platform/docker-compose.dokploy.yml`
- Environment: copy `grc-platform/deploy/dokploy.env.example`, then replace every `change-me` value
- Domains:
  - `grc.sc.deeptrustxai.com` to service `frontend`, port `80`, path `/`, HTTPS enabled
  - `auth.sc.deeptrustxai.com` to service `keycloak`, port `8080`, path `/`, HTTPS enabled

The Keycloak public browser endpoint is `https://auth.sc.deeptrustxai.com/auth`. Its management port `9000`, PostgreSQL, Redis, and RustFS remain private inside the compose network.

## Connector Contract

Create one distinct GRC connector token per tenant. The same token and tenant mapping must appear in:

- CloudGuard `CONNECTOR_CREDENTIALS_JSON`, with connector ID `grc-<tenant-id>` and scope `grc:read`
- GRC `CLOUDGUARD_CONNECTOR_CREDENTIALS_JSON`, keyed by the tenant ID

Never reuse the evidence connector token for GRC reads.

## Rollout Order

1. Deploy the GRC compose and confirm Keycloak readiness.
2. Add two temporary Keycloak users with different `organization_id` attributes.
3. Update CloudGuard with the public Keycloak issuer/JWKS settings and tenant-specific connector map.
4. Deploy CloudGuard. Its startup migration manager applies migrations 14 through 16 and now stops the deployment if any migration fails.
5. Run cross-tenant smoke tests, then remove the temporary users.

Do not enable the old development login, wildcard production origins, or caller-supplied identity headers.
