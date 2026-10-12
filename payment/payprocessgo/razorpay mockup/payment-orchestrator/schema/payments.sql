-- ============================================================
-- Payment Orchestrator Schema
-- Run this manually in psql before starting the server
-- ============================================================

CREATE DATABASE payments;

\c payments;

-- ============================================================
-- 1. users
-- email is current identity anchor
-- user_id column ready for future SSO immutable ID
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email TEXT NOT NULL,
    user_id TEXT, -- future SSO immutable ID slot
    role TEXT NOT NULL DEFAULT 'free', -- free | member | patron
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_email_unique UNIQUE (email),
    CONSTRAINT users_role_check CHECK (
        role IN ('free', 'member', 'patron')
    )
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE INDEX IF NOT EXISTS idx_users_user_id ON users (user_id);

-- ============================================================
-- 2. subscriptions
-- one row per purchase attempt
-- only one active subscription per user per product
-- ============================================================
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL, -- e.g. product_1_monthly
    product_id TEXT NOT NULL, -- e.g. product_1 | master
    billing_cycle TEXT NOT NULL, -- monthly | yearly
    razorpay_sub_id TEXT, -- filled after Razorpay call
    razorpay_plan_id TEXT, -- Razorpay's own plan ID
    status TEXT NOT NULL DEFAULT 'created',
    amount_paise INTEGER NOT NULL DEFAULT 0,
    current_start TIMESTAMPTZ,
    current_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT subscriptions_billing_check CHECK (
        billing_cycle IN ('monthly', 'yearly')
    ),
    CONSTRAINT subscriptions_status_check CHECK (
        status IN (
            'created',
            'authenticated',
            'active',
            'pending',
            'halted',
            'cancelled',
            'completed',
            'expired'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_subs_user_id ON subscriptions (user_id);

CREATE INDEX IF NOT EXISTS idx_subs_razorpay_sub_id ON subscriptions (razorpay_sub_id);

CREATE INDEX IF NOT EXISTS idx_subs_status ON subscriptions (status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_subs_one_active ON subscriptions (user_id, product_id)
WHERE
    status = 'active';

-- ============================================================
-- 3. webhook_events
-- idempotency log — prevents replay attacks
-- ============================================================
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT webhook_events_event_id_unique UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_event_id ON webhook_events (event_id);

-- ============================================================
-- 4. product_api_keys
-- each product gets its own key for /verify
-- ============================================================
CREATE TABLE IF NOT EXISTS product_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    product_id TEXT NOT NULL,
    api_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT product_api_keys_product_unique UNIQUE (product_id),
    CONSTRAINT product_api_keys_key_unique UNIQUE (api_key)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_product_id ON product_api_keys (product_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_key ON product_api_keys (api_key);