// Package config provides configuration loading from environment variables
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
)

// Config stores application configuration
type Config struct {
	// Server configuration
	Port string

	// Supabase configuration
	SupabaseURL            string
	SupabaseKey            string
	SupabaseServiceRoleKey string // Service role key for webhook operations
	SupabaseJWTSecret      string // optional: used to verify HS256 JWTs from Supabase

	// Stripe configuration
	StripeSecretKey      string
	StripeWebhookSecret  string
	StripePublishableKey string
	StripePriceID        string

	// Security configuration
	AllowedOrigins []string
	RateLimit      int // Requests per minute

	// Environment (development, production)
	Environment string
}

// Load loads configuration from environment variables
// It will attempt to load from .env file if present
func Load() (*Config, error) {
	// Try to load .env file from project root, ignore error if not found
	loadEnvFile()

	cfg := &Config{
		Port:        envOrDefault("PORT", "8080"),              // Changed default to 8080 for Cloud Run
		Environment: envOrDefault("ENVIRONMENT", "production"), // Default to production for Cloud Run
	}

	// Required configuration
	cfg.SupabaseURL = os.Getenv("SUPABASE_URL")
	if cfg.SupabaseURL == "" {
		return nil, errors.New("SUPABASE_URL is required")
	}

	cfg.SupabaseKey = os.Getenv("SUPABASE_KEY")
	if cfg.SupabaseKey == "" {
		return nil, errors.New("SUPABASE_KEY is required")
	}

	// Optional JWT secret for validating HS256 tokens
	cfg.SupabaseJWTSecret = os.Getenv("SUPABASE_JWT_SECRET")

	// Service role key for webhook operations
	cfg.SupabaseServiceRoleKey = os.Getenv("SUPABASE_SERVICE_ROLE_KEY")

	// Stripe configuration
	cfg.StripeSecretKey = os.Getenv("STRIPE_SECRET_KEY")
	if cfg.StripeSecretKey == "" {
		return nil, errors.New("STRIPE_SECRET_KEY is required")
	}

	cfg.StripeWebhookSecret = os.Getenv("STRIPE_WEBHOOK_SECRET")
	if cfg.StripeWebhookSecret == "" {
		return nil, errors.New("STRIPE_WEBHOOK_SECRET is required")
	}

	cfg.StripePublishableKey = os.Getenv("STRIPE_PUBLISHABLE_KEY")
	if cfg.StripePublishableKey == "" {
		return nil, errors.New("STRIPE_PUBLISHABLE_KEY is required")
	}

	cfg.StripePriceID = os.Getenv("STRIPE_PRICE_ID")
	if cfg.StripePriceID == "" {
		return nil, errors.New("STRIPE_PRICE_ID is required")
	}

	// Parse allowed origins
	origins := envOrDefault("ALLOWED_ORIGINS", "http://localhost:3001,cotex://,http://localhost:3000,http://localhost:8080,*.ngrok-free.app,*")
	cfg.AllowedOrigins = parseCommaSeparatedList(origins)

	// Parse rate limit
	rateLimit, err := strconv.Atoi(envOrDefault("RATE_LIMIT", "60"))
	if err != nil {
		rateLimit = 60 // Default to 60 rpm if parsing fails
	}
	cfg.RateLimit = rateLimit

	return cfg, nil
}

// loadEnvFile attempts to load .env from the project root directory
// It looks for the file in the current directory and parent directories
func loadEnvFile() {
	// Try the current directory first
	if err := godotenv.Load(); err == nil {
		return
	}

	// If not found, try to find the project root by looking for specific files/folders
	dir, err := os.Getwd()
	if err != nil {
		return // Can't determine current directory
	}

	// Look up to 5 directories up to find project root
	for i := 0; i < 5; i++ {
		// Check if this could be the project root (has go.mod or cmd folder)
		if fileExists(filepath.Join(dir, "go.mod")) ||
			dirExists(filepath.Join(dir, "cmd")) {
			// Try loading .env from this directory
			_ = godotenv.Load(filepath.Join(dir, ".env"))
			return
		}

		// Go up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			break // Reached the filesystem root
		}
		dir = parent
	}
}

// Helper function to check if a file exists
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Helper function to check if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// Helper function to get environment variable or default value
func envOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Parse comma separated list into slice of strings
func parseCommaSeparatedList(s string) []string {
	result := []string{}
	current := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
