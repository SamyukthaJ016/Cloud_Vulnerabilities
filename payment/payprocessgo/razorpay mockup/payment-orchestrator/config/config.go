package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port      string
	SSODomain string

	// Database
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// Razorpay
	RazorpayKeyID         string
	RazorpayKeySecret     string
	RazorpayWebhookSecret string

	// Plan IDs
	PlanIDs map[string]string

	// Product API Keys
	ProductAPIKeys map[string]string

	// CORS
	AllowedOrigins string

	// Mode
	SkeletonMode bool
}

func Load() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("WARNING: .env file not found, reading from environment")
	}

	cfg := &Config{
		Port:      getEnv("PORT", "8080"),
		SSODomain: getEnv("SSO_DOMAIN", "localhost:3000"),

		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "payments"),

		RazorpayKeyID:         getEnv("RAZORPAY_KEY_ID", ""),
		RazorpayKeySecret:     getEnv("RAZORPAY_KEY_SECRET", ""),
		RazorpayWebhookSecret: getEnv("RAZORPAY_WEBHOOK_SECRET", ""),

		AllowedOrigins: getEnv("ALLOWED_ORIGINS", "http://localhost:3000"),

		PlanIDs: map[string]string{
			"product_1_monthly": getEnv("PLAN_ID_PRODUCT_1_MONTHLY", ""),
			"product_1_yearly":  getEnv("PLAN_ID_PRODUCT_1_YEARLY", ""),
			"product_2_monthly": getEnv("PLAN_ID_PRODUCT_2_MONTHLY", ""),
			"product_2_yearly":  getEnv("PLAN_ID_PRODUCT_2_YEARLY", ""),
			"product_3_monthly": getEnv("PLAN_ID_PRODUCT_3_MONTHLY", ""),
			"product_3_yearly":  getEnv("PLAN_ID_PRODUCT_3_YEARLY", ""),
			"product_4_monthly": getEnv("PLAN_ID_PRODUCT_4_MONTHLY", ""),
			"product_4_yearly":  getEnv("PLAN_ID_PRODUCT_4_YEARLY", ""),
			"product_5_monthly": getEnv("PLAN_ID_PRODUCT_5_MONTHLY", ""),
			"product_5_yearly":  getEnv("PLAN_ID_PRODUCT_5_YEARLY", ""),
			"master_monthly":    getEnv("PLAN_ID_MASTER_MONTHLY", ""),
			"master_yearly":     getEnv("PLAN_ID_MASTER_YEARLY", ""),
		},

		ProductAPIKeys: map[string]string{
			"product_1": getEnv("API_KEY_PRODUCT_1", ""),
			"product_2": getEnv("API_KEY_PRODUCT_2", ""),
			"product_3": getEnv("API_KEY_PRODUCT_3", ""),
			"product_4": getEnv("API_KEY_PRODUCT_4", ""),
			"product_5": getEnv("API_KEY_PRODUCT_5", ""),
		},
	}

	cfg.SkeletonMode = cfg.RazorpayKeyID == "" || cfg.RazorpayKeySecret == ""

	if cfg.SkeletonMode {
		log.Println("WARNING: Razorpay keys missing — server starting in skeleton mode")
		log.Println("WARNING: POST /subscribe will return 503 until keys are set in .env")
	}

	missingPlanIDs := []string{}
	for key, val := range cfg.PlanIDs {
		if val == "" {
			missingPlanIDs = append(missingPlanIDs, key)
		}
	}
	if len(missingPlanIDs) > 0 {
		log.Printf("WARNING: %d Razorpay plan IDs not set in .env — fill when ready\n", len(missingPlanIDs))
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
