package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kamalsundar/payment-orchestrator/config"
	"github.com/kamalsundar/payment-orchestrator/store"
	_ "github.com/lib/pq"
)

type postgresDB struct {
	db *sql.DB
}

// New opens a connection and verifies it with a ping
func New(cfg *config.Config) (store.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: failed to open: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("postgres: failed to ping: %w", err)
	}

	return &postgresDB{db: db}, nil
}

// Close shuts down the connection pool
func (p *postgresDB) Close() error {
	return p.db.Close()
}

// ============================================================
// User operations
// ============================================================

func (p *postgresDB) GetOrCreateUser(ctx context.Context, email string) (*store.User, error) {
	query := `
		INSERT INTO users (email)
		VALUES ($1)
		ON CONFLICT (email) DO UPDATE SET updated_at = NOW()
		RETURNING id, email, COALESCE(user_id, ''), role, created_at, updated_at
	`
	row := p.db.QueryRowContext(ctx, query, email)
	return scanUser(row)
}

func (p *postgresDB) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	query := `
		SELECT id, email, COALESCE(user_id, ''), role, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	row := p.db.QueryRowContext(ctx, query, email)
	return scanUser(row)
}

func (p *postgresDB) GetUserByInternalID(ctx context.Context, id string) (*store.User, error) {
	query := `
		SELECT id, email, COALESCE(user_id, ''), role, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)
	return scanUser(row)
}

func (p *postgresDB) UpdateUserRole(ctx context.Context, email string, role string) error {
	query := `
		UPDATE users
		SET role = $1, updated_at = NOW()
		WHERE email = $2
	`
	result, err := p.db.ExecContext(ctx, query, role, email)
	if err != nil {
		return fmt.Errorf("postgres: update role: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: update role rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("postgres: update role: user not found for email %s", email)
	}
	return nil
}

// ============================================================
// Subscription operations
// ============================================================

func (p *postgresDB) CreateSubscription(ctx context.Context, sub *store.Subscription) error {
	query := `
		INSERT INTO subscriptions (
			user_id, plan_id, product_id, billing_cycle,
			razorpay_sub_id, razorpay_plan_id, status, amount_paise
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := p.db.ExecContext(ctx, query,
		sub.UserID,
		sub.PlanID,
		sub.ProductID,
		sub.BillingCycle,
		sub.RazorpaySubID,
		sub.RazorpayPlanID,
		sub.Status,
		sub.AmountPaise,
	)
	if err != nil {
		return fmt.Errorf("postgres: create subscription: %w", err)
	}
	return nil
}

func (p *postgresDB) GetSubscriptionByRazorpayID(ctx context.Context, razorpaySubID string) (*store.Subscription, error) {
	query := `
		SELECT
			id, user_id, plan_id, product_id, billing_cycle,
			COALESCE(razorpay_sub_id, ''), COALESCE(razorpay_plan_id, ''),
			status, amount_paise,
			current_start, current_end,
			created_at, updated_at
		FROM subscriptions
		WHERE razorpay_sub_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, razorpaySubID)
	return scanSubscription(row)
}

func (p *postgresDB) GetActiveSubscription(ctx context.Context, userID string, productID string) (*store.Subscription, error) {
	query := `
		SELECT
			id, user_id, plan_id, product_id, billing_cycle,
			COALESCE(razorpay_sub_id, ''), COALESCE(razorpay_plan_id, ''),
			status, amount_paise,
			current_start, current_end,
			created_at, updated_at
		FROM subscriptions
		WHERE user_id = $1
		  AND product_id = $2
		  AND status = 'active'
		LIMIT 1
	`
	row := p.db.QueryRowContext(ctx, query, userID, productID)
	return scanSubscription(row)
}

func (p *postgresDB) UpdateSubscriptionStatus(
	ctx context.Context,
	razorpaySubID string,
	status string,
	start *time.Time,
	end *time.Time,
) error {
	query := `
		UPDATE subscriptions
		SET status = $1,
		    current_start = $2,
		    current_end = $3,
		    updated_at = NOW()
		WHERE razorpay_sub_id = $4
	`
	_, err := p.db.ExecContext(ctx, query, status, start, end, razorpaySubID)
	if err != nil {
		return fmt.Errorf("postgres: update subscription status: %w", err)
	}
	return nil
}

// ============================================================
// Webhook idempotency
// ============================================================

func (p *postgresDB) IsWebhookEventProcessed(ctx context.Context, eventID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM webhook_events WHERE event_id = $1)`
	var exists bool
	err := p.db.QueryRowContext(ctx, query, eventID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("postgres: check webhook event: %w", err)
	}
	return exists, nil
}

func (p *postgresDB) MarkWebhookEventProcessed(ctx context.Context, eventID string, eventType string, payload []byte) error {
	query := `
		INSERT INTO webhook_events (event_id, event_type, payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (event_id) DO NOTHING
	`
	_, err := p.db.ExecContext(ctx, query, eventID, eventType, payload)
	if err != nil {
		return fmt.Errorf("postgres: mark webhook event: %w", err)
	}
	return nil
}

// ============================================================
// Internal scan helpers — never exported
// ============================================================

func scanUser(row *sql.Row) (*store.User, error) {
	u := &store.User{}
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.UserID,
		&u.Role,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: scan user: %w", err)
	}
	return u, nil
}

func scanSubscription(row *sql.Row) (*store.Subscription, error) {
	s := &store.Subscription{}
	err := row.Scan(
		&s.ID,
		&s.UserID,
		&s.PlanID,
		&s.ProductID,
		&s.BillingCycle,
		&s.RazorpaySubID,
		&s.RazorpayPlanID,
		&s.Status,
		&s.AmountPaise,
		&s.CurrentStart,
		&s.CurrentEnd,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: scan subscription: %w", err)
	}
	return s, nil
}
