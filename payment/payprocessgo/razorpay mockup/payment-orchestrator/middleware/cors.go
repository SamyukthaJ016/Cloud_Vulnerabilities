package middleware

import (
	"net/http"
	"strings"

	"github.com/go-chi/cors"
	"github.com/kamalsundar/payment-orchestrator/config"
)

func CORS(cfg *config.Config) func(http.Handler) http.Handler {
	origins := strings.Split(cfg.AllowedOrigins, ",")

	return cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-API-Key", "X-Request-ID"},
		AllowCredentials: false,
		MaxAge:           300,
	})
}
