package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kamalsundar/payment-orchestrator/api"
	"github.com/kamalsundar/payment-orchestrator/config"
	appMiddleware "github.com/kamalsundar/payment-orchestrator/middleware"
	"github.com/kamalsundar/payment-orchestrator/store/postgres"
)

func main() {
	cfg := config.Load()

	// Connect to database
	db, err := postgres.New(cfg)
	if err != nil {
		log.Fatalf("could not connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Database connected successfully")

	r := chi.NewRouter()

	// Base middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	// CORS
	r.Use(appMiddleware.CORS(cfg))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		mode := "live"
		if cfg.SkeletonMode {
			mode = "skeleton"
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","mode":"%s"}`, mode)
	})

	// API routes
	r.Get("/plans", api.HandleGetPlans)
	r.Post("/subscribe", api.HandleSubscribe(cfg, db))

	// TODO Phase 6: mount POST /webhook
	r.Post("/webhook", api.HandleWebhook(cfg, db))
	// TODO Phase 5: mount GET /status/:id
	r.Get("/status/{id}", api.HandleStatus(db))

	// TODO Phase 7: mount GET /verify
	r.Get("/verify", api.HandleVerify(cfg, db))

	// Serve UI
	fs := http.FileServer(http.Dir("./ui"))
	r.Handle("/ui/*", http.StripPrefix("/ui", fs))

	addr := ":" + cfg.Port
	log.Printf("Payment Orchestrator running on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
