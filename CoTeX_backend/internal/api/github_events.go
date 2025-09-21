// Package api provides API handlers for the application
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/brandon/cotex-backend/internal/webhook"
	"github.com/rs/zerolog"
)

// EventStore defines the interface for accessing GitHub events
type EventStore interface {
	GetUndeliveredEvents(userID string) ([]database.GitHubEvent, error)
	MarkEventAsDelivered(eventID string) error
	DeleteExpiredEvents() error
}

// GitHubEventHandler handles GitHub event retrieval requests
type GitHubEventHandler struct {
	db  EventStore
	hub webhook.Hub
	log zerolog.Logger
}

// NewGitHubEventHandler creates a new GitHub event handler
func NewGitHubEventHandler(db EventStore, hub webhook.Hub) *GitHubEventHandler {
	return &GitHubEventHandler{
		db:  db,
		hub: hub,
		log: logger.Logger(map[string]interface{}{"component": "github_events"}),
	}
}

// GetEvents handles requests to retrieve undelivered GitHub events
// This is called when a user comes online after being offline
func (h *GitHubEventHandler) GetEvents(w http.ResponseWriter, r *http.Request, userID string) {
	log := h.log.With().Str("user_id", userID).Logger()
	log.Info().Msg("GetEvents: retrieving undelivered events")

	// Delete expired events first as a housekeeping task
	// Don't block the request if this fails
	if err := h.db.DeleteExpiredEvents(); err != nil {
		log.Error().Err(err).Msg("Failed to delete expired events")
	}

	// Retrieve undelivered events for the user
	events, err := h.db.GetUndeliveredEvents(userID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to retrieve undelivered events")
		http.Error(w, "Failed to retrieve events", http.StatusInternalServerError)
		return
	}

	log.Info().Int("count", len(events)).Msg("Retrieved undelivered events")

	// Convert events to response format
	response := make([]EventResponse, 0, len(events))
	for _, event := range events {
		// Parse the payload
		var payload interface{}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Msg("Failed to parse event payload")
			continue
		}

		// Format the created time
		createdAt, err := time.Parse(time.RFC3339, event.CreatedAt)
		if err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Str("time", event.CreatedAt).
				Msg("Failed to parse event creation time")
			createdAt = time.Now()
		}

		// Add to response
		response = append(response, EventResponse{
			ID:        event.ID,
			RepoName:  event.RepoName,
			EventType: event.EventType,
			Payload:   payload,
			CreatedAt: createdAt,
		})

		// Mark this event as delivered
		if err := h.db.MarkEventAsDelivered(event.ID); err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Msg("Failed to mark event as delivered")
		}
	}

	// Return the events as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// EventResponse represents a GitHub event in the API response
type EventResponse struct {
	ID        string      `json:"id"`
	RepoName  string      `json:"repo_name"`
	EventType string      `json:"event_type"`
	Payload   interface{} `json:"payload"`
	CreatedAt time.Time   `json:"created_at"`
}
