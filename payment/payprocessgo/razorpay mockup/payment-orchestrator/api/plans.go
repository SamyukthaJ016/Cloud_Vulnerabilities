package api

import (
	"net/http"

	"github.com/kamalsundar/payment-orchestrator/core/finance"
)

type PlanResponse struct {
	ID           string   `json:"id"`
	ProductID    string   `json:"product_id"`
	ProductName  string   `json:"product_name"`
	BillingCycle string   `json:"billing_cycle"`
	AmountPaise  int      `json:"amount_paise"`
	AmountINR    float64  `json:"amount_inr"`
	Currency     string   `json:"currency"`
	Role         string   `json:"role"`
	Features     []string `json:"features"`
}

func HandleGetPlans(w http.ResponseWriter, r *http.Request) {
	plans := finance.AllPlans

	response := make([]PlanResponse, 0, len(plans))
	for _, p := range plans {
		response = append(response, PlanResponse{
			ID:           p.ID,
			ProductID:    p.ProductID,
			ProductName:  p.ProductName,
			BillingCycle: p.BillingCycle,
			AmountPaise:  p.AmountPaise,
			AmountINR:    float64(p.AmountPaise) / 100,
			Currency:     p.Currency,
			Role:         p.Role,
			Features:     p.Features,
		})
	}

	writeJSON(w, http.StatusOK, response)
}
