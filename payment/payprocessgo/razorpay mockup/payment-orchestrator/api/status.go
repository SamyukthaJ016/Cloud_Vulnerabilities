package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kamalsundar/payment-orchestrator/store"
)

func HandleStatus(db store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		razorpaySubID := chi.URLParam(r, "id")
		if razorpaySubID == "" {
			writeError(w, http.StatusBadRequest, "subscription id required")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		sub, err := db.GetSubscriptionByRazorpayID(ctx, razorpaySubID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not fetch status")
			return
		}
		if sub == nil {
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"subscription_id": sub.ID,
			"status":          sub.Status,
			"product_id":      sub.ProductID,
			"plan_id":         sub.PlanID,
			"billing_cycle":   sub.BillingCycle,
		})
	}
}