package api

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/kamalsundar/payment-orchestrator/config"
	"github.com/kamalsundar/payment-orchestrator/core/entitlement"
	"github.com/kamalsundar/payment-orchestrator/core/finance"
	"github.com/kamalsundar/payment-orchestrator/store"
)

// RazorpayWebhookPayload is the top level envelope Razorpay sends
type RazorpayWebhookPayload struct {
	Entity    string         `json:"entity"`
	AccountID string         `json:"account_id"`
	Event     string         `json:"event"`
	Contains  []string       `json:"contains"`
	Payload   WebhookPayload `json:"payload"`
}

type WebhookPayload struct {
	Subscription WebhookEntity `json:"subscription"`
	Payment      WebhookEntity `json:"payment"`
}

type WebhookEntity struct {
	Entity RazorpaySubscription `json:"entity"`
}

type RazorpaySubscription struct {
	ID           string `json:"id"`
	PlanID       string `json:"plan_id"`
	Status       string `json:"status"`
	CurrentStart *int64 `json:"current_start"`
	CurrentEnd   *int64 `json:"current_end"`
}

func HandleWebhook(cfg *config.Config, db store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Read raw body — must happen before any decode
		// Razorpay signature is computed against raw bytes
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read body")
			return
		}

		// Verify HMAC-SHA256 signature
		signature := r.Header.Get("X-Razorpay-Signature")
		if err := finance.VerifyWebhookSignature(body, signature, cfg.RazorpayWebhookSecret); err != nil {
			log.Printf("webhook: signature verification failed: %v", err)
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}

		// Decode payload
		var event RazorpayWebhookPayload
		if err := json.Unmarshal(body, &event); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}

		eventID := event.AccountID + "_" + event.Event + "_" +
			event.Payload.Subscription.Entity.ID

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// Idempotency check — silently discard duplicate events
		processed, err := db.IsWebhookEventProcessed(ctx, eventID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "idempotency check failed")
			return
		}
		if processed {
			log.Printf("webhook: duplicate event %s — discarded", eventID)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Mark event as processed before doing work
		// Prevents race condition on duplicate delivery
		if err := db.MarkWebhookEventProcessed(ctx, eventID, event.Event, body); err != nil {
			writeError(w, http.StatusInternalServerError, "could not mark event")
			return
		}

		// Route event to correct handler
		sub := event.Payload.Subscription.Entity
		switch event.Event {

		case "subscription.activated":
			if err := handleActivated(ctx, db, sub); err != nil {
				log.Printf("webhook: activated handler error: %v", err)
			}

		case "subscription.charged":
			if err := handleActivated(ctx, db, sub); err != nil {
				log.Printf("webhook: charged handler error: %v", err)
			}

		case "subscription.halted",
			"subscription.cancelled",
			"subscription.completed",
			"subscription.expired":
			if err := handleDeactivated(ctx, db, sub, event.Event); err != nil {
				log.Printf("webhook: deactivated handler error: %v", err)
			}

		default:
			log.Printf("webhook: unhandled event type %s", event.Event)
		}

		// Always return 200 to Razorpay
		// If we return non-200 Razorpay will retry indefinitely
		w.WriteHeader(http.StatusOK)
	}
}

// handleActivated marks subscription active and assigns role
func handleActivated(ctx context.Context, db store.DB, sub RazorpaySubscription) error {
	var start, end *time.Time
	if sub.CurrentStart != nil {
		t := time.Unix(*sub.CurrentStart, 0)
		start = &t
	}
	if sub.CurrentEnd != nil {
		t := time.Unix(*sub.CurrentEnd, 0)
		end = &t
	}

	if err := db.UpdateSubscriptionStatus(ctx, sub.ID, "active", start, end); err != nil {
		return err
	}

	// Find subscription to get user email and product
	dbSub, err := db.GetSubscriptionByRazorpayID(ctx, sub.ID)
	if err != nil || dbSub == nil {
		return err
	}

	// Resolve role from product
	role := entitlement.RoleForPlan(dbSub.ProductID)

	// Get user by internal ID to find email
	// We stored user.ID in subscriptions.user_id
	// GetOrCreateUser won't help here — need email
	// So we look up via subscription's user_id → users table
	user, err := getUserByID(ctx, db, dbSub.UserID)
	if err != nil || user == nil {
		return err
	}

	return db.UpdateUserRole(ctx, user.Email, role)
}

// handleDeactivated marks subscription with terminal status and revokes role
func handleDeactivated(ctx context.Context, db store.DB, sub RazorpaySubscription, event string) error {
	statusMap := map[string]string{
		"subscription.halted":    "halted",
		"subscription.cancelled": "cancelled",
		"subscription.completed": "completed",
		"subscription.expired":   "expired",
	}

	status, ok := statusMap[event]
	if !ok {
		status = "expired"
	}

	if err := db.UpdateSubscriptionStatus(ctx, sub.ID, status, nil, nil); err != nil {
		return err
	}

	dbSub, err := db.GetSubscriptionByRazorpayID(ctx, sub.ID)
	if err != nil || dbSub == nil {
		return err
	}

	user, err := getUserByID(ctx, db, dbSub.UserID)
	if err != nil || user == nil {
		return err
	}

	// Revoke role back to free
	return db.UpdateUserRole(ctx, user.Email, entitlement.RoleFree)
}

// getUserByID is a local helper — looks up user by UUID
// store.DB interface uses email as anchor, so we add a raw lookup here
func getUserByID(ctx context.Context, db store.DB, userID string) (*store.User, error) {
	return db.GetUserByInternalID(ctx, userID)
}
