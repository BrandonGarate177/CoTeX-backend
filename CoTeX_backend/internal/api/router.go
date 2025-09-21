// Package api provides HTTP API route definitions
package api

import (
	"context"
	"net/http"

	"github.com/brandon/cotex-backend/internal/auth"
	"github.com/brandon/cotex-backend/internal/config"
	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/brandon/cotex-backend/internal/middleware"
	"github.com/brandon/cotex-backend/internal/stripe"
	"github.com/brandon/cotex-backend/internal/webhook"
	"github.com/brandon/cotex-backend/internal/websocket"
	"github.com/rs/zerolog"
)

// Router handles HTTP routing
type Router struct {
	authenticator *auth.Authenticator
	db            *database.Client
	webhookDB     database.Store // Service role client for webhook operations
	webhookHub    *webhook.Hub
	wsUpgrader    *webhook.WebSocketUpgrader
	githubHandler *websocket.GitHubHandler
	handler       *Handler
	rateLimiter   *middleware.RateLimiter
	config        *config.Config
	log           zerolog.Logger
}

// NewRouter creates a new router instance
func NewRouter(
	authenticator *auth.Authenticator,
	db *database.Client,
	webhookDB database.Store,
	webhookHub *webhook.Hub,
	wsUpgrader *webhook.WebSocketUpgrader,
	cfg *config.Config,
) *Router {
	// Create the rate limiter
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit)

	// Create the Stripe service
	stripeSvc := stripe.NewService(db, cfg.StripeWebhookSecret, cfg.StripePriceID)

	// Create the API handler with webhook database for GitHub event operations
	handler := NewHandlerWithWebhookDB(db, webhookDB, webhookHub, wsUpgrader, stripeSvc)

	// Create the GitHub webhook handler with service role client for webhook operations
	githubHandler := websocket.NewGitHubHandlerWithEnv(webhookDB, webhookHub, cfg.Environment)

	return &Router{
		authenticator: authenticator,
		db:            db,
		webhookDB:     webhookDB,
		webhookHub:    webhookHub,
		wsUpgrader:    wsUpgrader,
		githubHandler: githubHandler,
		handler:       handler,
		rateLimiter:   rateLimiter,
		config:        cfg,
		log:           logger.Logger(map[string]interface{}{"component": "router"}),
	}
}

// Setup registers all routes and returns an HTTP handler
func (r *Router) Setup() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/health", r.handler.HealthCheck)

	// GitHub webhook endpoint with repo ID - no auth required, uses webhook secrets
	mux.HandleFunc("/api/webhooks/github/", func(w http.ResponseWriter, req *http.Request) {
		r.githubHandler.HandleWebhook(w, req)
	})

	// Stripe webhook endpoint - no auth required, uses webhook signature verification
	mux.HandleFunc("/webhooks/stripe", func(w http.ResponseWriter, req *http.Request) {
		r.handler.StripeWebhookHandler(w, req)
	})

	// Authenticated endpoints

	// WebSocket endpoint with authentication middleware
	mux.HandleFunc("/ws", func(w http.ResponseWriter, req *http.Request) {
		r.withAuth(r.handler.WebSocketHandler)(w, req)
	})

	// Repository tracking endpoint with authentication
	mux.HandleFunc("/api/repos", func(w http.ResponseWriter, req *http.Request) {
		r.withAuth(r.handler.RepoHandler)(w, req)
	})

	// GitHub events endpoint with authentication
	mux.HandleFunc("/api/github-events", func(w http.ResponseWriter, req *http.Request) {
		r.withAuth(r.handler.GitHubEventsHandler)(w, req)
	})

	// Recent event IDs endpoint with authentication
	mux.HandleFunc("/api/github-events/recent", func(w http.ResponseWriter, req *http.Request) {
		r.withAuth(r.handler.RecentEventIDsHandler)(w, req)
	})

	// Event by ID endpoint with authentication
	mux.HandleFunc("/api/github-events/event", func(w http.ResponseWriter, req *http.Request) {
		r.withAuth(r.handler.EventByIDHandler)(w, req)
	})

	// Stripe checkout session creation endpoint with authentication
	mux.HandleFunc("/api/checkout", func(w http.ResponseWriter, req *http.Request) {
		r.withAuth(r.handler.CreateCheckoutSession)(w, req)
	})

	// Wrap the entire mux with common middleware
	var handler http.Handler = mux

	// Add CORS middleware for HTTP requests
	handler = middleware.CORSMiddleware(r.config.AllowedOrigins)(handler)

	// Add origin check middleware for WebSocket connections (keep this for backward compatibility)
	handler = middleware.OriginCheckMiddleware(r.config.AllowedOrigins)(handler)

	// Add rate limiting middleware
	handler = r.rateLimiter.Middleware(handler)

	// Add request logging middleware
	handler = middleware.LoggingMiddleware(handler)

	return handler
}

// withAuth wraps an http.HandlerFunc with JWT authentication
func (r *Router) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Do NOT handle OPTIONS here - CORS middleware already handled it

		// Log the request details for debugging
		r.log.Info().
			Str("method", req.Method).
			Str("path", req.URL.Path).
			Str("authorization", req.Header.Get("Authorization")).
			Str("user_agent", req.UserAgent()).
			Msg("Processing authenticated request")

		token, err := auth.ExtractToken(req)
		if err != nil {
			r.log.Warn().
				Err(err).
				Str("path", req.URL.Path).
				Str("authorization_header", req.Header.Get("Authorization")).
				Msg("Authentication failed: no token")
			// Return 401 but DO NOT clobber CORS headers already set
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := r.authenticator.ValidateToken(token)
		if err != nil {
			r.log.Warn().
				Err(err).
				Str("path", req.URL.Path).
				Msg("Authentication failed: invalid token")
			// Return 401 but DO NOT clobber CORS headers already set
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Store user info in context
		ctx := req.Context()
		ctx = context.WithValue(ctx, auth.UserContextKey, claims)

		// Log successful authentication
		r.log.Debug().
			Str("user_id", claims.UserID).
			Str("path", req.URL.Path).
			Msg("User authenticated")

		// Call the next handler with the updated context
		next(w, req.WithContext(ctx))
	}
}
