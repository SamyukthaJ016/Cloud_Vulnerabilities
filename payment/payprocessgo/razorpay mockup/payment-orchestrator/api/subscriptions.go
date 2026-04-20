package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kamalsundar/payment-orchestrator/config"
	"github.com/kamalsundar/payment-orchestrator/core/finance"
	"github.com/kamalsundar/payment-orchestrator/store"
)

type SubscribeRequest struct {
	PlanID string `json:"plan_id"`
	Email  string `json:"email"`
}

type SubscribeResponse struct {
	SubscriptionID string `json:"subscription_id"`
	RazorpaySubID  string `json:"razorpay_sub_id"`
	Status         string `json:"status"`
}

func HandleSubscribe(cfg *config.Config, db store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Skeleton mode — keys not configured yet
		if cfg.SkeletonMode {
			writeError(w, http.StatusServiceUnavailable,
				"payment service not configured yet — Razorpay keys missing")
			return
		}

		// Decode request
		var req SubscribeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.PlanID == "" {
			writeError(w, http.StatusBadRequest, "plan_id is required")
			return
		}

		if req.Email == "" {
			writeError(w, http.StatusBadRequest, "email is required")
			return
		}

		// Validate plan exists — browser cannot spoof a fake plan
		plan := finance.GetPlanByID(req.PlanID)
		if plan == nil {
			writeError(w, http.StatusBadRequest, "unknown plan_id")
			return
		}

		// Get Razorpay plan ID from config
		razorpayPlanID := cfg.PlanIDs[req.PlanID]
		if razorpayPlanID == "" {
			writeError(w, http.StatusServiceUnavailable,
				"plan not yet configured in Razorpay — check .env")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// Get or create user
		user, err := db.GetOrCreateUser(ctx, req.Email)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve user")
			return
		}

		// Block duplicate active subscription for same product
		existing, err := db.GetActiveSubscription(ctx, user.ID, plan.ProductID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check existing subscription")
			return
		}
		if existing != nil {
			writeError(w, http.StatusConflict,
				"active subscription already exists for this product")
			return
		}

		// TODO Phase 6: call Razorpay API here to create subscription
		// razorpaySubID, err := razorpay.CreateSubscription(razorpayPlanID, cfg)
		// For now this point is unreachable in skeleton mode
		// but structure is ready for when keys arrive
		_ = razorpayPlanID

		// Save subscription record as 'created'
		sub := &store.Subscription{
			UserID:         user.ID,
			PlanID:         plan.ID,
			ProductID:      plan.ProductID,
			BillingCycle:   plan.BillingCycle,
			RazorpaySubID:  "", // filled after Razorpay call
			RazorpayPlanID: razorpayPlanID,
			Status:         "created",
			AmountPaise:    plan.AmountPaise,
		}

		if err := db.CreateSubscription(ctx, sub); err != nil {
			writeError(w, http.StatusInternalServerError, "could not save subscription")
			return
		}

		writeJSON(w, http.StatusOK, SubscribeResponse{
			SubscriptionID: sub.ID,
			RazorpaySubID:  "",
			Status:         "created",
		})
	}
}
