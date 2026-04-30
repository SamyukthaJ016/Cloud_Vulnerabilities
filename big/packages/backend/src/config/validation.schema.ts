import * as Joi from 'joi';

/**
 * Validates env at app boot. Fails fast if required vars are missing.
 * Extend this when a new module adds env vars — keep it alphabetical inside each section.
 */
export const validationSchema = Joi.object({
  // App
  NODE_ENV: Joi.string().valid('development', 'test', 'staging', 'production').default('development'),
  APP_PORT: Joi.number().default(3000),
  APP_BASE_URL: Joi.string().uri().required(),
  FRONTEND_BASE_URL: Joi.string().uri().required(),
  CORS_ORIGINS: Joi.string().required(),

  // Database
  DATABASE_URL: Joi.string().uri({ scheme: ['postgresql', 'postgres'] }).required(),

  // Redis
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().default(6379),
  REDIS_PASSWORD: Joi.string().allow(''),

  // JWT
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRES_IN: Joi.string().default('1h'),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),

  // Google OAuth
  GOOGLE_CLIENT_ID: Joi.string().required(),
  GOOGLE_CLIENT_SECRET: Joi.string().required(),
  GOOGLE_CALLBACK_URL: Joi.string().uri().required(),

  // Razorpay (optional in dev — required before billing module is wired)
  RAZORPAY_KEY_ID: Joi.string().allow(''),
  RAZORPAY_KEY_SECRET: Joi.string().allow(''),
  RAZORPAY_WEBHOOK_SECRET: Joi.string().allow(''),

  // Vault
  VAULT_ADDR: Joi.string().uri().required(),
  VAULT_TOKEN: Joi.string().required(),
  VAULT_KV_MOUNT: Joi.string().default('secret'),
  VAULT_ORG_PATH_PREFIX: Joi.string().default('orgs'),

  // Scanner services. Per-scanner pairs (SCANNER_<N>_BASE_URL +
  // SCANNER_<N>_SHARED_SECRET) are discovered dynamically at boot by
  // ScannerSyncService — Joi only declares the callback URL here. Unknown env
  // vars are allowed by ConfigModule, so adding a slot needs no code change.
  SCANNER_CALLBACK_BASE_URL: Joi.string().uri().required(),
  CLOUDGUARD_BASE_URL: Joi.string().uri().default('https://cloud-vulnerabilities.vercel.app'),
  CLOUDGUARD_USER_ID: Joi.string().default('anonymous'),

  // S3 (optional for v1)
  S3_ENDPOINT: Joi.string().uri().allow(''),
  S3_REGION: Joi.string().allow(''),
  S3_BUCKET: Joi.string().allow(''),
  S3_ACCESS_KEY: Joi.string().allow(''),
  S3_SECRET_KEY: Joi.string().allow(''),

  // Logging
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'log', 'debug', 'verbose').default('debug'),
});
