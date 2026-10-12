package store

import (
	"context"
	"time"
)

// User represents a row in the users table
type User struct {
	ID        string
	Email     string
	UserID    string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Subscription represents a row in the subscriptions table
type Subscription struct {
	ID             string
	UserID         string
	PlanID         string
	ProductID      string
	BillingCycle   string
	RazorpaySubID  string
	RazorpayPlanID string
	Status         string
	AmountPaise    int
	CurrentStart   *time.Time
	CurrentEnd     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// DB is the contract every storage backend must satisfy
// Real implementation lives in store/postgres/postgres.go
// Never add SQL here — this file is interface only
type DB interface {
	// User operations
	GetOrCreateUser(ctx context.Context, email string) (*User, error)
	UpdateUserRole(ctx context.Context, email string, role string) error

	// Subscription operations
	CreateSubscription(ctx context.Context, sub *Subscription) error
	GetSubscriptionByRazorpayID(ctx context.Context, razorpaySubID string) (*Subscription, error)
	GetActiveSubscription(ctx context.Context, userID string, productID string) (*Subscription, error)
	UpdateSubscriptionStatus(ctx context.Context, razorpaySubID string, status string, start *time.Time, end *time.Time) error

	// Webhook idempotency
	IsWebhookEventProcessed(ctx context.Context, eventID string) (bool, error)
	MarkWebhookEventProcessed(ctx context.Context, eventID string, eventType string, payload []byte) error

	// Verify
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByInternalID(ctx context.Context, id string) (*User, error)

	// Cleanup
	Close() error
}
