// Package main provides the entry point for the CoTeX backend server
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brandon/cotex-backend/internal/api"
	"github.com/brandon/cotex-backend/internal/auth"
	"github.com/brandon/cotex-backend/internal/config"
	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/brandon/cotex-backend/internal/webhook"
	"github.com/stripe/stripe-go/v78"
)

func main() {

	// Loading configs && logger ################################
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	logger.Setup(cfg)
	log := logger.Logger(map[string]interface{}{"component": "main"})

	log.Info().
		Str("port", cfg.Port).
		Str("environment", cfg.Environment).
		Msg("Starting CoTeX backend server...")

	// Initialize Stripe
	stripe.Key = cfg.StripeSecretKey
	log.Info().Msg("Stripe initialized")

	// Supabase Auth && database ################################
	authenticator := auth.NewAuthenticator(cfg.SupabaseURL, cfg.SupabaseJWTSecret)
	log.Info().Msg("JWT authenticator initialized")

	// Use service role key for main database operations
	db, err := database.NewClient(cfg.SupabaseURL, cfg.SupabaseServiceRoleKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Supabase client")
	}
	log.Info().Msg("Supabase client initialized with service role key")

	// Create service role client for webhook operations (same as main client)
	var webhookDB database.Store = db
	log.Info().Msg("Supabase service role client initialized for webhook operations")

	// WebSocket upgrader && hub ################################
	wsUpgrader := webhook.NewWebSocketUpgrader(cfg.AllowedOrigins)
	log.Info().
		Strs("allowed_origins", cfg.AllowedOrigins).
		Msg("WebSocket upgrader initialized")

	// Create and start the WebSocket hub #################################
	hub := webhook.NewHub()
	go hub.Run()
	log.Info().Msg("WebSocket hub started")

	// Setup HTTP router and handlers ################################
	router := api.NewRouter(authenticator, db, webhookDB, hub, wsUpgrader, cfg)
	handler := router.Setup()
	log.Info().Msg("API router configured")

	// Start the HTTP server with graceful shutdown ################################
	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
	}

	// Start server in a separate goroutine to allow graceful shutdown
	go func() {
		log.Info().Str("port", cfg.Port).Msg("Server listening on port")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server error")
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Server shutting down...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server stopped")
}
