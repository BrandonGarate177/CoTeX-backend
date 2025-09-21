// Package api provides HTTP API route definitions
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/brandon/cotex-backend/internal/auth"
	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/brandon/cotex-backend/internal/stripe"
	"github.com/brandon/cotex-backend/internal/webhook"

	//"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Handler contains the handlers for API endpoints
type Handler struct {
	db         database.Store
	webhookDB  database.Store // Service role client for GitHub event operations
	hub        *webhook.Hub
	wsUpgrader *webhook.WebSocketUpgrader
	stripeSvc  *stripe.Service
	log        zerolog.Logger
}

// NewHandler creates a new Handler instance
func NewHandler(db database.Store, hub *webhook.Hub, wsUpgrader *webhook.WebSocketUpgrader, stripeSvc *stripe.Service) *Handler {
	return &Handler{
		db:         db,
		webhookDB:  db, // Use same client for both if no separate webhook DB provided
		hub:        hub,
		wsUpgrader: wsUpgrader,
		stripeSvc:  stripeSvc,
		log:        logger.Logger(map[string]interface{}{"component": "api_handler"}),
	}
}

// NewHandlerWithWebhookDB creates a new Handler instance with separate webhook database client
func NewHandlerWithWebhookDB(db database.Store, webhookDB database.Store, hub *webhook.Hub, wsUpgrader *webhook.WebSocketUpgrader, stripeSvc *stripe.Service) *Handler {
	return &Handler{
		db:         db,
		webhookDB:  webhookDB,
		hub:        hub,
		wsUpgrader: wsUpgrader,
		stripeSvc:  stripeSvc,
		log:        logger.Logger(map[string]interface{}{"component": "api_handler"}),
	}
}

// HealthCheck handles health check requests
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// RepoRequest represents a request to track a repository
type RepoRequest struct {
	RepoName      string `json:"repo_name"`
	WebhookSecret string `json:"webhook_secret"`
}

// RepoHandler handles repository tracking requests
func (h *Handler) RepoHandler(w http.ResponseWriter, r *http.Request) {
	// Add detailed logging for debugging
	h.log.Info().
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("user_agent", r.UserAgent()).
		Str("authorization", r.Header.Get("Authorization")).
		Msg("RepoHandler called")

	// Get user from context
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		h.log.Warn().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Msg("Authentication failed: no user in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Create user-specific logger
	log := logger.WithUserID(user.UserID)
	log.Info().
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Msg("User authenticated, processing request")

	switch r.Method {
	case http.MethodGet:
		// Check if ID parameter is provided for getting a specific repository
		repoID := r.URL.Query().Get("id")
		if repoID != "" {
			h.getRepoByID(w, r, user.UserID, repoID, log)
		} else {
			// List all repositories
			h.listRepos(w, r, user.UserID, log)
		}
	case http.MethodPost:
		// Add repository
		h.addRepo(w, r, user.UserID, log)
	case http.MethodDelete:
		// Delete repository
		h.deleteRepo(w, r, user.UserID, log)
	default:
		log.Warn().Str("method", r.Method).Msg("Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// listRepos lists all repositories for a user
func (h *Handler) listRepos(w http.ResponseWriter, _ *http.Request, userID string, log zerolog.Logger) {
	log.Info().Str("user_id", userID).Msg("Starting to list repositories")

	repos, err := h.db.ListRepositories(userID)
	if err != nil {
		log.Error().Err(err).Str("user_id", userID).Msg("Error listing repositories")
		http.Error(w, "Failed to list repositories", http.StatusInternalServerError)
		return
	}

	log.Info().Str("user_id", userID).Int("count", len(repos)).Msg("Successfully retrieved repositories")

	log.Info().Int("count", len(repos)).Msg("Retrieved user repositories")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(repos); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// addRepo adds a new repository for tracking
func (h *Handler) addRepo(w http.ResponseWriter, r *http.Request, userID string, log zerolog.Logger) {
	var req RepoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn().Err(err).Msg("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RepoName == "" || req.WebhookSecret == "" {
		log.Warn().Msg("Missing required fields")
		http.Error(w, "Repository name and webhook secret are required", http.StatusBadRequest)
		return
	}

	repo, err := h.db.AddRepository(userID, req.RepoName, req.WebhookSecret)
	if err != nil {
		if errors.Is(err, database.ErrRepoLimitReached) {
			// Return 403 Forbidden when user has reached their repo limit
			log.Warn().Msg("Repository limit reached")
			http.Error(w, "Repository limit reached", http.StatusForbidden)
			return
		}
		if errors.Is(err, database.ErrRepoAlreadyExists) {
			log.Warn().Str("repo", req.RepoName).Msg("Repository already exists")
			http.Error(w, "Repository already exists", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("repo", req.RepoName).Msg("Error adding repository")
		http.Error(w, "Failed to add repository", http.StatusInternalServerError)
		return
	}

	// Notify the user about the successful repository addition
	message := webhook.NewSystemMessage(fmt.Sprintf("Repository %s was successfully added", req.RepoName))
	h.hub.BroadcastToUser(userID, message)

	// Generate the webhook URL for the client
	webhookURL := fmt.Sprintf("/api/webhooks/github/%s", repo.ID)

	// Prepare the response
	response := map[string]interface{}{
		"repository":  repo,
		"webhook_url": webhookURL,
	}

	log.Info().
		Str("repo_id", repo.ID).
		Str("repo_name", repo.RepoName).
		Msg("Repository added successfully")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// deleteRepo removes repository tracking
func (h *Handler) deleteRepo(w http.ResponseWriter, r *http.Request, userID string, log zerolog.Logger) {
	repoID := r.URL.Query().Get("id")
	repoName := r.URL.Query().Get("name")

	if repoID != "" {
		// Delete by ID
		repo, err := h.db.GetRepositoryByID(repoID)
		if err != nil {
			log.Error().Err(err).Str("repo_id", repoID).Msg("Error getting repository")
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Verify the repo belongs to this user
		if repo.UserID != userID {
			log.Warn().
				Str("repo_id", repoID).
				Str("user_id", userID).
				Str("repo_user_id", repo.UserID).
				Msg("Unauthorized repository access")
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}

		if err := h.db.DeleteRepositoryByID(repoID); err != nil {
			log.Error().Err(err).Str("repo_id", repoID).Msg("Error deleting repository")
			http.Error(w, "Failed to delete repository", http.StatusInternalServerError)
			return
		}

		// Notify the user about the successful repository deletion
		message := webhook.NewSystemMessage(fmt.Sprintf("Repository %s was successfully removed", repo.RepoName))
		h.hub.BroadcastToUser(userID, message)

	} else if repoName != "" {
		// Delete by name (legacy support)
		if err := h.db.DeleteRepository(userID, repoName); err != nil {
			log.Error().Err(err).Str("repo_name", repoName).Msg("Error deleting repository")
			http.Error(w, "Failed to delete repository", http.StatusInternalServerError)
			return
		}

		// Notify the user about the successful repository deletion
		message := webhook.NewSystemMessage(fmt.Sprintf("Repository %s was successfully removed", repoName))
		h.hub.BroadcastToUser(userID, message)
	} else {
		log.Warn().Msg("Missing repository identifier")
		http.Error(w, "Repository ID or name is required", http.StatusBadRequest)
		return
	}

	log.Info().
		Str("repo_id", repoID).
		Str("repo_name", repoName).
		Msg("Repository deleted successfully")

	w.WriteHeader(http.StatusNoContent)
}

// WebSocketHandler handles WebSocket connection requests
func (h *Handler) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Serve WebSocket connection with the user's ID
	h.wsUpgrader.ServeWs(h.hub, w, r, user.UserID)
}

// GitHubEventsHandler handles requests for retrieving GitHub events for users who were offline
func (h *Handler) GitHubEventsHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from context (added by auth middleware)
	userClaims, ok := r.Context().Value(auth.UserContextKey).(*auth.UserClaims)
	if !ok {
		h.log.Error().Msg("Failed to get user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get all undelivered events for the user
	events, err := h.db.GetUndeliveredEvents(userClaims.UserID)
	if err != nil {
		h.log.Error().
			Err(err).
			Str("user_id", userClaims.UserID).
			Msg("Failed to retrieve undelivered GitHub events")
		http.Error(w, "Failed to retrieve events", http.StatusInternalServerError)
		return
	}

	// Clean up expired events as a housekeeping task
	// This is a non-blocking operation - we don't wait for it to complete
	go func() {
		if err := h.db.DeleteExpiredEvents(); err != nil {
			h.log.Error().Err(err).Msg("Failed to delete expired events")
		}
	}()

	// Prepare the response
	type eventResponse struct {
		ID        string          `json:"id"`
		RepoID    string          `json:"repo_id"`
		RepoName  string          `json:"repo_name"`
		EventType string          `json:"event_type"`
		Payload   json.RawMessage `json:"payload"`
		CreatedAt string          `json:"created_at"`
	}

	responses := make([]eventResponse, 0, len(events))
	for _, event := range events {
		responses = append(responses, eventResponse{
			ID:        event.ID,
			RepoID:    event.RepoID,
			RepoName:  event.RepoName,
			EventType: event.EventType,
			Payload:   event.Payload,
			CreatedAt: event.CreatedAt,
		})

		// Mark this event as delivered
		if err := h.db.MarkEventAsDelivered(event.ID); err != nil {
			h.log.Error().
				Err(err).
				Str("event_id", event.ID).
				Msg("Failed to mark event as delivered")
		}
	}

	h.log.Info().
		Str("user_id", userClaims.UserID).
		Int("event_count", len(events)).
		Msg("Retrieved undelivered GitHub events")

	// Return the events as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responses); err != nil {
		h.log.Error().
			Err(err).
			Msg("Failed to encode GitHub events response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// RecentEventIDsHandler handles requests for the last N GitHub event IDs
func (h *Handler) RecentEventIDsHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from context (added by auth middleware)
	userClaims, ok := r.Context().Value(auth.UserContextKey).(*auth.UserClaims)
	if !ok {
		h.log.Error().Msg("Failed to get user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user wants full event data or just IDs
	includePayload := r.URL.Query().Get("include_payload") == "true"

	// Check if user wants to filter by repo_id
	repoID := r.URL.Query().Get("repo_id")

	if includePayload {
		// Get recent events with full data using webhook DB (service role)
		var events []database.GitHubEvent
		var err error

		if repoID != "" {
			// Filter by repo_id if provided
			events, err = h.webhookDB.GetUndeliveredEventsByRepo(userClaims.UserID, repoID)
		} else {
			// Get all events for user
			events, err = h.webhookDB.GetUndeliveredEvents(userClaims.UserID)
		}

		if err != nil {
			h.log.Error().
				Err(err).
				Str("user_id", userClaims.UserID).
				Str("repo_id", repoID).
				Msg("Failed to retrieve recent GitHub events with payload")
			http.Error(w, "Failed to retrieve events", http.StatusInternalServerError)
			return
		}

		// Limit to 5 most recent and prepare full response
		limit := 5
		if len(events) > limit {
			events = events[:limit]
		}

		type fullEventResponse struct {
			ID        string          `json:"id"`
			RepoID    string          `json:"repo_id"`
			RepoName  string          `json:"repo_name"`
			EventType string          `json:"event_type"`
			Payload   json.RawMessage `json:"payload"` // Raw payload (for debugging/audit)
			CreatedAt string          `json:"created_at"`
			ExpiresAt string          `json:"expires_at"`
		}

		var fullEvents []fullEventResponse
		for _, event := range events {
			fullEvents = append(fullEvents, fullEventResponse{
				ID:        event.ID,
				RepoID:    event.RepoID,
				RepoName:  event.RepoName,
				EventType: event.EventType,
				Payload:   event.Payload,
				CreatedAt: event.CreatedAt,
				ExpiresAt: event.ExpiresAt,
			})
		}

		response := map[string]interface{}{
			"events": fullEvents,
			"count":  len(fullEvents),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			h.log.Error().Err(err).Msg("Failed to encode response")
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	} else {
		// Get just the event IDs (existing behavior)
		var eventIDs []string
		var err error

		if repoID != "" {
			// Filter by repo_id if provided
			eventIDs, err = h.webhookDB.GetRecentEventIDsByRepo(userClaims.UserID, repoID, 5)
		} else {
			// Get all event IDs for user
			eventIDs, err = h.webhookDB.GetRecentEventIDs(userClaims.UserID, 5)
		}

		if err != nil {
			h.log.Error().
				Err(err).
				Str("user_id", userClaims.UserID).
				Str("repo_id", repoID).
				Msg("Failed to retrieve recent GitHub event IDs")
			http.Error(w, "Failed to retrieve event IDs", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"event_ids": eventIDs,
			"count":     len(eventIDs),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			h.log.Error().Err(err).Msg("Failed to encode response")
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// EventByIDHandler handles requests for a specific GitHub event by ID or most recent event
func (h *Handler) EventByIDHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from context (added by auth middleware)
	userClaims, ok := r.Context().Value(auth.UserContextKey).(*auth.UserClaims)
	if !ok {
		h.log.Error().Msg("Failed to get user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user wants the most recent event or a specific event by ID
	eventID := r.URL.Query().Get("id")
	getMostRecent := r.URL.Query().Get("recent") == "true"

	var event *database.GitHubEvent
	var err error

	if getMostRecent {
		// Get the most recent undelivered event for the user with proper ordering
		eventIDs, err := h.webhookDB.GetRecentEventIDs(userClaims.UserID, 1)
		if err != nil {
			h.log.Error().
				Err(err).
				Str("user_id", userClaims.UserID).
				Msg("Failed to retrieve most recent GitHub event ID")
			http.Error(w, "Failed to retrieve events", http.StatusInternalServerError)
			return
		}

		if len(eventIDs) == 0 {
			http.Error(w, "No recent events found", http.StatusNotFound)
			return
		}

		// Get the most recent event by its ID
		event, err = h.webhookDB.GetEventByID(eventIDs[0])
		if err != nil {
			h.log.Error().
				Err(err).
				Str("event_id", eventIDs[0]).
				Str("user_id", userClaims.UserID).
				Msg("Failed to retrieve most recent GitHub event")
			http.Error(w, "Failed to retrieve event", http.StatusInternalServerError)
			return
		}

		if event == nil {
			http.Error(w, "Event not found", http.StatusNotFound)
			return
		}
	} else if eventID != "" {
		// Get event by specific ID (existing behavior)
		if eventID == "" {
			http.Error(w, "Event ID is required when not using recent=true", http.StatusBadRequest)
			return
		}

		// Get the event by ID using webhook DB (service role)
		event, err = h.webhookDB.GetEventByID(eventID)
		if err != nil {
			h.log.Error().
				Err(err).
				Str("event_id", eventID).
				Str("user_id", userClaims.UserID).
				Msg("Failed to retrieve GitHub event")
			http.Error(w, "Failed to retrieve event", http.StatusInternalServerError)
			return
		}

		if event == nil {
			http.Error(w, "Event not found", http.StatusNotFound)
			return
		}
	}

	// Verify that the event belongs to the requesting user
	if event.UserID != userClaims.UserID {
		h.log.Warn().
			Str("event_id", event.ID).
			Str("event_user_id", event.UserID).
			Str("requesting_user_id", userClaims.UserID).
			Msg("User attempted to access event that doesn't belong to them")
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}

	// Prepare the response with full event details
	type eventResponse struct {
		ID        string          `json:"id"`
		RepoID    string          `json:"repo_id"`
		RepoName  string          `json:"repo_name"`
		EventType string          `json:"event_type"`
		Payload   json.RawMessage `json:"payload"`
		CreatedAt string          `json:"created_at"`
		ExpiresAt string          `json:"expires_at"`
	}

	response := eventResponse{
		ID:        event.ID,
		RepoID:    event.RepoID,
		RepoName:  event.RepoName,
		EventType: event.EventType,
		Payload:   event.Payload,
		CreatedAt: event.CreatedAt,
		ExpiresAt: event.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Error().Err(err).Msg("Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// getRepoByID retrieves a specific repository by its ID
func (h *Handler) getRepoByID(w http.ResponseWriter, r *http.Request, userID, repoID string, log zerolog.Logger) {
	repo, err := h.db.GetRepositoryByID(repoID)
	if err != nil {
		log.Error().Err(err).Str("repo_id", repoID).Msg("Error getting repository")
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	// Verify the repo belongs to this user
	if repo.UserID != userID {
		log.Warn().
			Str("repo_id", repoID).
			Str("user_id", userID).
			Str("repo_user_id", repo.UserID).
			Msg("Unauthorized repository access")
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	log.Info().
		Str("repo_id", repo.ID).
		Str("repo_name", repo.RepoName).
		Msg("Retrieved repository")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(repo); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// CreateCheckoutSession creates a Stripe checkout session for upgrading to pro
func (h *Handler) CreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user from context
	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		h.log.Warn().Msg("Authentication failed: no user in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user profile to get email
	profile, err := h.db.GetUserProfile(user.UserID)
	if err != nil {
		h.log.Error().Err(err).Str("user_id", user.UserID).Msg("Failed to get user profile")
		http.Error(w, "Failed to get user profile", http.StatusInternalServerError)
		return
	}

	// Create checkout session
	session, err := h.stripeSvc.CreateCheckoutSession(user.UserID, profile.Email)
	if err != nil {
		h.log.Error().Err(err).Str("user_id", user.UserID).Msg("Failed to create checkout session")
		http.Error(w, "Failed to create checkout session", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"url": session.URL,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// StripeWebhookHandler handles Stripe webhook events
func (h *Handler) StripeWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Process the webhook
	if err := h.stripeSvc.HandleWebhook(r); err != nil {
		h.log.Error().Err(err).Msg("Failed to process webhook")
		http.Error(w, "Webhook processing failed", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
