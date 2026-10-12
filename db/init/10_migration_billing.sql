BEGIN;

ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS billing_role VARCHAR(32) NOT NULL DEFAULT 'free';

ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();

ALTER TABLE user_profiles
    DROP CONSTRAINT IF EXISTS user_profiles_billing_role_check;

ALTER TABLE user_profiles
    ADD CONSTRAINT user_profiles_billing_role_check
    CHECK (billing_role IN ('free', 'member', 'patron'));

CREATE TABLE IF NOT EXISTS billing_subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL
        REFERENCES user_profiles(user_id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    product_name TEXT,
    billing_cycle TEXT NOT NULL,
    role_granted TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'created',
    amount_paise INTEGER NOT NULL DEFAULT 0,
    currency VARCHAR(12) NOT NULL DEFAULT 'INR',
    razorpay_sub_id TEXT,
    razorpay_plan_id TEXT,
    razorpay_customer_id TEXT,
    customer_email TEXT,
    current_start TIMESTAMPTZ,
    current_end TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT billing_subscriptions_billing_cycle_check
        CHECK (billing_cycle IN ('monthly', 'yearly')),
    CONSTRAINT billing_subscriptions_role_check
        CHECK (role_granted IN ('member', 'patron')),
    CONSTRAINT billing_subscriptions_status_check
        CHECK (status IN ('created', 'authenticated', 'active', 'pending', 'halted', 'cancelled', 'completed', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_user_id
    ON billing_subscriptions(user_id);

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_product_id
    ON billing_subscriptions(product_id);

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_status
    ON billing_subscriptions(status);

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_razorpay_sub_id
    ON billing_subscriptions(razorpay_sub_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_subscriptions_one_active
    ON billing_subscriptions(user_id, product_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS billing_webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_webhook_events_event_id
    ON billing_webhook_events(event_id);

CREATE TABLE IF NOT EXISTS billing_product_api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id TEXT NOT NULL UNIQUE,
    api_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_product_api_keys_product_id
    ON billing_product_api_keys(product_id);

CREATE INDEX IF NOT EXISTS idx_billing_product_api_keys_api_key
    ON billing_product_api_keys(api_key);

DROP TRIGGER IF EXISTS tr_billing_subscriptions_updated_at ON billing_subscriptions;

CREATE TRIGGER tr_billing_subscriptions_updated_at
BEFORE UPDATE ON billing_subscriptions
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS tr_user_profiles_updated_at ON user_profiles;

CREATE TRIGGER tr_user_profiles_updated_at
BEFORE UPDATE ON user_profiles
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

COMMIT;
