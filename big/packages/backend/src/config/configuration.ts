/**
 * Typed config loader. Access via `configService.get<T>('key.path')`.
 * Validation of the underlying env is in ./validation.schema.ts.
 */
export const configuration = () => ({
  app: {
    env: process.env.NODE_ENV,
    port: parseInt(process.env.APP_PORT ?? '3000', 10),
    baseUrl: process.env.APP_BASE_URL,
    frontendBaseUrl: process.env.FRONTEND_BASE_URL,
    corsOrigins: process.env.CORS_ORIGINS,
    logLevel: process.env.LOG_LEVEL ?? 'debug',
  },
  db: {
    url: process.env.DATABASE_URL,
  },
  redis: {
    host: process.env.REDIS_HOST ?? 'localhost',
    port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
    password: process.env.REDIS_PASSWORD,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN ?? '1h',
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',
  },
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl: process.env.GOOGLE_CALLBACK_URL,
  },
  razorpay: {
    keyId: process.env.RAZORPAY_KEY_ID,
    keySecret: process.env.RAZORPAY_KEY_SECRET,
    webhookSecret: process.env.RAZORPAY_WEBHOOK_SECRET,
  },
  vault: {
    addr: process.env.VAULT_ADDR,
    token: process.env.VAULT_TOKEN,
    kvMount: process.env.VAULT_KV_MOUNT ?? 'secret',
    orgPathPrefix: process.env.VAULT_ORG_PATH_PREFIX ?? 'orgs',
  },
  scanners: {
    // Per-scanner SCANNER_<N>_BASE_URL / SCANNER_<N>_SHARED_SECRET env pairs are
    // discovered dynamically by `modules/scanners/scanner-env.ts` — no static
    // entries here. Adding a scanner = set the two env vars and restart.
    callbackBaseUrl: process.env.SCANNER_CALLBACK_BASE_URL,
  },
  cloudguard: {
    baseUrl: process.env.CLOUDGUARD_BASE_URL ?? 'https://cloud-vulnerabilities.vercel.app',
    userId: process.env.CLOUDGUARD_USER_ID ?? 'anonymous',
  },
  s3: {
    endpoint: process.env.S3_ENDPOINT,
    region: process.env.S3_REGION,
    bucket: process.env.S3_BUCKET,
    accessKey: process.env.S3_ACCESS_KEY,
    secretKey: process.env.S3_SECRET_KEY,
  },
});
