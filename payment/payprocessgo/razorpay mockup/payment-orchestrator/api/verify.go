package api

import (
	"context"
	"net/http"
	"time"

	"github.com/kamalsundar/payment-orchestrator/config"
	"github.com/kamalsundar/payment-orchestrator/core/entitlement"
	"github.com/kamalsundar/payment-orchestrator/store"
)

func HandleVerify(cfg *config.Config, db store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Validate API key — each product has its own key
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			writeError(w, http.StatusUnauthorized, "missing X-API-Key header")
			return
		}

		validKey := false
		for _, key := range cfg.ProductAPIKeys {
			if key == apiKey && key != "" {
				validKey = true
				break
			}
		}
		if !validKey {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}

		// Read query params
		email := r.URL.Query().Get("email")
		productID := r.URL.Query().Get("product")

		if email == "" {
			writeError(w, http.StatusBadRequest, "email is required")
			return
		}
		if productID == "" {
			writeError(w, http.StatusBadRequest, "product is required")
			return
		}

		if !entitlement.IsValidProduct(productID) {
			writeError(w, http.StatusBadRequest, "unknown product")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Look up user
		user, err := db.GetUserByEmail(ctx, email)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not look up user")
			return
		}
		if user == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"email":      email,
				"product":    productID,
				"has_access": false,
				"role":       entitlement.RoleFree,
				"reason":     "user not found",
			})
			return
		}

		// Patron gets access to everything
		if user.Role == entitlement.RolePatron {
			writeJSON(w, http.StatusOK, map[string]any{
				"email":      email,
				"product":    productID,
				"has_access": true,
				"role":       user.Role,
				"reason":     "patron access",
			})
			return
		}

		// Member — check if they have active sub for this product
		activeSub, err := db.GetActiveSubscription(ctx, user.ID, productID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check subscription")
			return
		}

		hasAccess := activeSub != nil
		reason := "no active subscription"
		if hasAccess {
			reason = "active subscription"
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"email":      email,
			"product":    productID,
			"has_access": hasAccess,
			"role":       user.Role,
			"reason":     reason,
		})
	}
}
