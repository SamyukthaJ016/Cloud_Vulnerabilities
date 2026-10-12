# Current Scanner Architecture

The supported scanner choices are AWS, GCP, Kubernetes, and uploaded IaC files.
CloudFox and container/image checks remain underlying tools, not additional
standalone scanner choices.

## Retired Paths

- The old cookie/URL-token SSO login and token exchange are retired. Browser
  APIs require verified Keycloak JWTs; tenant identity comes from the token.
- Direct dispatch to the legacy worker HTTP service is replaced by the
  PostgreSQL scan-job queue. The compatibility endpoint
  `POST /scan/multi-cloud` now returns the same queued-job response as
  `POST /api/jobs/scan`.
- The global GRC sync trigger returns HTTP 410. Use the GRC portal and
  tenant-specific connector credentials. Scanner results and evidence remain
  available through the authenticated connector APIs.
- Legacy saved filesystem-path/container profiles are not scanner choices.
  Upload IaC files through the current scanner interface. The old folder-profile
  upload endpoint returns HTTP 410.
- Vercel routes use the current application entrypoint instead of the old
  duplicated static pages.

## Preserved Capabilities

Keycloak login, tenant isolation, four scanners, queued workers, job retries and
cancellation, demo-lab lifecycles, evidence storage, GRC connectors, and billing
remain available. Billing uses the verified Keycloak user and still enforces
subscriptions when the billing-enforcement flag is enabled.

Historical credential/profile records are preserved in the database for
compatibility. Unused legacy modules and deployment examples are not the current
production entrypoints.

AWS demo provisioning remains disabled until a dedicated sandbox account,
allowed account ID, and scoped provisioning credentials are configured.
