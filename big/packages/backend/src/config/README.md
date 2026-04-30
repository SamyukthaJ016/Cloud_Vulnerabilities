# config/

Centralized env loading + validation. Every backend module reads config via `ConfigService.get<T>('path')`.

## Files

- `configuration.ts` — typed shape of all config, read from `process.env`.
- `validation.schema.ts` — Joi schema; fails app boot if required env is missing.
- `index.ts` — barrel export.

## Adding a new env variable

1. Add it to `.env.example` (root) with a sensible default or placeholder.
2. Add it to `configuration.ts` under the right section.
3. Add it to `validation.schema.ts` with correct type + required/default.
4. Use it in your module: `constructor(private config: ConfigService) {}` → `this.config.get<string>('section.key')`.

## Sections

| Section | Owner module(s) | Keys |
|---|---|---|
| `app` | platform | port, base URLs, CORS, log level |
| `db` | platform (prisma) | `DATABASE_URL` |
| `redis` | platform (queue) | host, port, password |
| `jwt` | auth | secret, expiresIn, refresh secret/expiresIn |
| `google` | auth | client id, secret, callback url |
| `razorpay` | billing, billing-webhooks | key id, key secret, webhook secret |
| `vault` | secrets | addr, token, mount, path prefix |
| `scanners` | scanner-clients | per-scanner base URL + shared secret, global callback URL |
| `s3` | findings (artifacts) | endpoint, region, bucket, credentials |

## Notes

- Config is validated once at boot — no need to re-check shape at runtime.
- Never hardcode secrets in source; always go through env.
- `ConfigService` is globally available because `ConfigModule.forRoot({ isGlobal: true })` is set in `app.module.ts`.
