// Package websocket provides GitHub webhook event handling functionality
package websocket

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/brandon/cotex-backend/internal/webhook"
	"github.com/rs/zerolog"
)

// GitHubEvent represents a GitHub webhook event
type GitHubEvent struct {
	// GitHub event type
	Type string

	// Repository information
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`

	// Sender information
	Sender struct {
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	} `json:"sender"`

	// Other fields will be passed as-is to the client
	// We don't need to define all GitHub webhook fields
}

// Broadcaster is the minimal interface needed from the hub for broadcasting
// This allows injecting a mock in tests.
type Broadcaster interface {
	BroadcastToUser(userID string, message *webhook.Message)
}

// RepoGetter is the minimal database interface needed for webhook handling
// to fetch a repository by ID.
type RepoGetter interface {
	GetRepositoryByID(repoID string) (*database.Repository, error)
	SaveGitHubEvent(event *database.GitHubEvent) error
}

// GitHubHandler handles GitHub webhook requests
type GitHubHandler struct {
	db          RepoGetter
	hub         Broadcaster
	log         zerolog.Logger
	environment string // Track environment for debugging
}

// NewGitHubHandler creates a new GitHub webhook handler
func NewGitHubHandler(db RepoGetter, hub Broadcaster) *GitHubHandler {
	return &GitHubHandler{
		db:          db,
		hub:         hub,
		log:         logger.Logger(map[string]interface{}{"component": "github_webhook"}),
		environment: "production", // Default to production
	}
}

// NewGitHubHandlerWithEnv creates a new GitHub webhook handler with environment info
func NewGitHubHandlerWithEnv(db RepoGetter, hub Broadcaster, environment string) *GitHubHandler {
	return &GitHubHandler{
		db:          db,
		hub:         hub,
		log:         logger.Logger(map[string]interface{}{"component": "github_webhook"}),
		environment: environment,
	}
}

// verifySignature verifies that the webhook came from GitHub using the secret
// Supports both SHA1 (X-Hub-Signature) and SHA256 (X-Hub-Signature-256)
func (h *GitHubHandler) verifySignature(body []byte, signature string, secret string) bool {
	// Check if it's SHA256 signature
	if strings.HasPrefix(signature, "sha256=") {
		signatureHash := strings.TrimPrefix(signature, "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expectedHash := hex.EncodeToString(mac.Sum(nil))
		return hmac.Equal([]byte(signatureHash), []byte(expectedHash))
	}

	// Check if it's SHA1 signature
	if strings.HasPrefix(signature, "sha1=") {
		signatureHash := strings.TrimPrefix(signature, "sha1=")
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write(body)
		expectedHash := hex.EncodeToString(mac.Sum(nil))
		return hmac.Equal([]byte(signatureHash), []byte(expectedHash))
	}

	return false
}

// extractRepoIDFromPath extracts the repository ID from the URL path
func extractRepoIDFromPath(path string) (string, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return "", errors.New("invalid URL path format")
	}

	// Path format is /api/webhooks/github/:repo_id
	repoID := parts[len(parts)-1]
	if repoID == "" {
		return "", errors.New("repository ID not found in path")
	}

	return repoID, nil
}

// extractCommitMessage extracts the commit message from a GitHub webhook payload
// It handles different event types and returns the most relevant commit message
func extractCommitMessage(eventType string, payload []byte) string {
	var rawPayload map[string]interface{}
	if err := json.Unmarshal(payload, &rawPayload); err != nil {
		return ""
	}

	switch eventType {
	case "push":
		// For push events, get the message from head_commit
		if headCommit, ok := rawPayload["head_commit"].(map[string]interface{}); ok {
			if message, ok := headCommit["message"].(string); ok {
				return message
			}
		}
		// Fallback: get the first commit's message
		if commits, ok := rawPayload["commits"].([]interface{}); ok && len(commits) > 0 {
			if firstCommit, ok := commits[0].(map[string]interface{}); ok {
				if message, ok := firstCommit["message"].(string); ok {
					return message
				}
			}
		}

	case "pull_request":
		// For pull request events, get the PR title
		if pr, ok := rawPayload["pull_request"].(map[string]interface{}); ok {
			if title, ok := pr["title"].(string); ok {
				return title
			}
		}

	case "issues":
		// For issue events, get the issue title
		if issue, ok := rawPayload["issue"].(map[string]interface{}); ok {
			if title, ok := issue["title"].(string); ok {
				return title
			}
		}

	case "release":
		// For release events, get the release name or tag name
		if release, ok := rawPayload["release"].(map[string]interface{}); ok {
			if name, ok := release["name"].(string); ok && name != "" {
				return name
			}
			if tagName, ok := release["tag_name"].(string); ok {
				return tagName
			}
		}
	}

	return "" // Return empty string if no commit message found
}

// HandleWebhook processes GitHub webhook events
// Path format: /api/webhooks/github/:repo_id
func (h *GitHubHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request for debugging
	h.log.Info().
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("user_agent", r.UserAgent()).
		Str("content_type", r.Header.Get("Content-Type")).
		Str("x_github_event", r.Header.Get("X-GitHub-Event")).
		Str("x_hub_signature_256", r.Header.Get("X-Hub-Signature-256")).
		Msg("Received webhook request")

	// Extract repository ID from URL path
	repoID, err := extractRepoIDFromPath(r.URL.Path)
	if err != nil {
		h.log.Error().Err(err).Str("path", r.URL.Path).Msg("Failed to extract repository ID from path")
		http.Error(w, "Invalid repository path", http.StatusBadRequest)
		return
	}

	h.log.Info().Str("repo_id", repoID).Msg("Extracted repository ID from path")

	// Get the repository by ID
	repo, err := h.db.GetRepositoryByID(repoID)
	if err != nil {
		// Log the error but don't reveal to potential attackers that the repo doesn't exist
		h.log.Error().Err(err).Str("repo_id", repoID).Msg("Repository not found")
		w.WriteHeader(http.StatusOK) // Return 200 to avoid exposing which repos exist
		return
	}

	// Create repo-specific logger
	repoLog := h.log.With().
		Str("repo_id", repoID).
		Str("repo_name", repo.RepoName).
		Str("user_id", repo.UserID).
		Logger()

	// Get the GitHub event type
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		repoLog.Warn().Msg("Missing X-GitHub-Event header")
		if h.environment == "development" {
			http.Error(w, "Missing X-GitHub-Event header", http.StatusBadRequest)
		} else {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		return
	}
	repoLog.Info().Str("event_type", eventType).Msg("Found GitHub event type")

	// Get the signature - try both SHA256 and SHA1
	signature := r.Header.Get("X-Hub-Signature-256")
	signatureType := "sha256"
	if signature == "" {
		signature = r.Header.Get("X-Hub-Signature")
		signatureType = "sha1"
	}

	if signature == "" {
		repoLog.Warn().Msg("Missing both X-Hub-Signature-256 and X-Hub-Signature headers")
		if h.environment == "development" {
			http.Error(w, "Missing webhook signature header", http.StatusBadRequest)
		} else {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		return
	}
	repoLog.Info().Str("signature", signature).Str("type", signatureType).Msg("Found webhook signature")

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		repoLog.Error().Err(err).Msg("Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	repoLog.Info().Int("body_size", len(body)).Msg("Read request body")

	// Verify the signature with the repository's webhook secret
	repoLog.Info().Str("webhook_secret_length", fmt.Sprintf("%d", len(repo.WebhookSecret))).Msg("Verifying webhook signature")
	if !h.verifySignature(body, signature, repo.WebhookSecret) {
		repoLog.Warn().Msg("Invalid webhook signature")
		w.WriteHeader(http.StatusOK) // Return 200 to avoid exposing which signatures are valid
		return
	}
	repoLog.Info().Msg("Webhook signature verified successfully")

	// Parse the event based on content type
	var event GitHubEvent
	var rawPayload []byte
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		// Parse as JSON
		if err := json.Unmarshal(body, &event); err != nil {
			bodyPreview := string(body)
			if len(bodyPreview) > 200 {
				bodyPreview = bodyPreview[:200] + "..."
			}
			repoLog.Error().Err(err).Str("body_preview", bodyPreview).Msg("Invalid JSON payload")
			if h.environment == "development" {
				http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
			} else {
				http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			}
			return
		}
		rawPayload = body
		repoLog.Info().Msg("Successfully parsed GitHub event JSON")
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Parse as form data
		formData, err := url.ParseQuery(string(body))
		if err != nil {
			repoLog.Error().Err(err).Msg("Failed to parse form data")
			if h.environment == "development" {
				http.Error(w, fmt.Sprintf("Invalid form data: %v", err), http.StatusBadRequest)
			} else {
				http.Error(w, "Invalid form data", http.StatusBadRequest)
			}
			return
		}

		// Extract payload from form data
		payloadStr := formData.Get("payload")
		if payloadStr == "" {
			repoLog.Error().Msg("Missing payload in form data")
			http.Error(w, "Missing payload in form data", http.StatusBadRequest)
			return
		}

		// Parse the JSON payload
		if err := json.Unmarshal([]byte(payloadStr), &event); err != nil {
			payloadPreview := payloadStr
			if len(payloadPreview) > 200 {
				payloadPreview = payloadPreview[:200] + "..."
			}
			repoLog.Error().Err(err).Str("payload_preview", payloadPreview).Msg("Invalid JSON in form payload")
			if h.environment == "development" {
				http.Error(w, fmt.Sprintf("Invalid JSON in form payload: %v", err), http.StatusBadRequest)
			} else {
				http.Error(w, "Invalid JSON in form payload", http.StatusBadRequest)
			}
			return
		}
		rawPayload = []byte(payloadStr)
		repoLog.Info().Msg("Successfully parsed GitHub event from form data")
	} else {
		repoLog.Error().Str("content_type", contentType).Msg("Unsupported content type")
		http.Error(w, "Unsupported content type", http.StatusBadRequest)
		return
	}

	// Set the event type
	event.Type = eventType

	repoLog.Info().
		Str("event", eventType).
		Str("repo_full_name", event.Repository.FullName).
		Msg("Received GitHub webhook event")

	// Extract commit message from the payload
	commitMessage := extractCommitMessage(eventType, body)

	// Parse the webhook payload to create an event summary
	deliveryID := r.Header.Get("X-GitHub-Delivery")
	if deliveryID == "" {
		deliveryID = fmt.Sprintf("webhook-%d", time.Now().UnixNano())
	}

	eventSummary, err := webhook.ParseGitHubWebhook(deliveryID, eventType, body)
	if err != nil {
		repoLog.Error().Err(err).Msg("Failed to parse webhook payload for summary")
		// Continue without summary - don't fail the request
	}

	// Create a message for the WebSocket clients using the event summary
	var messagePayload interface{}
	if eventSummary != nil {
		messagePayload = eventSummary
	} else {
		// Fallback to raw event if summary parsing failed
		messagePayload = event
	}

	message := webhook.NewGithubEventMessage(
		repo.UserID,
		event.Repository.FullName,
		eventType,
		messagePayload,
	)

	// Broadcast to the specific user
	h.hub.BroadcastToUser(repo.UserID, message)
	repoLog.Debug().Msg("Event broadcasted to user")

	// Store the event in the database with 2-week expiration
	expirationTime := time.Now().AddDate(0, 0, 14) // 2 weeks from now

	dbEvent := &database.GitHubEvent{
		UserID:        repo.UserID,
		RepoID:        repoID,
		RepoName:      event.Repository.FullName,
		EventType:     eventType,
		Payload:       rawPayload, // Store the full raw JSON payload
		CommitMessage: commitMessage,
		ExpiresAt:     expirationTime.Format(time.RFC3339),
		IsDelivered:   false, // Initially not delivered
	}

	if err := h.db.SaveGitHubEvent(dbEvent); err != nil {
		repoLog.Error().Err(err).Msg("Failed to save event to database")
		// Don't fail the request if database storage fails
		// Just log the error and continue
	} else {
		repoLog.Debug().Msg("Event saved to database")
	}

	// Respond with success
	w.WriteHeader(http.StatusOK)
}
