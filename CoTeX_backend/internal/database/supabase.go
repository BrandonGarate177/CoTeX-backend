// Package database provides Supabase database integration for repo tracking
package database

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

var (
	// ErrRepoLimitReached is returned when a user has reached their repo limit
	ErrRepoLimitReached = errors.New("repository limit reached for user")
	// ErrRepoAlreadyExists is returned when attempting to add a repo that already exists
	ErrRepoAlreadyExists = errors.New("repository already exists")
	// ErrRepositoryNotFound is returned when a repository cannot be found
	ErrRepositoryNotFound = errors.New("repository not found")
)

// SubscriptionTier represents a user's subscription level
type SubscriptionTier string

const (
	// FreeTier is the default free subscription
	FreeTier SubscriptionTier = "free"
	// ProTier is the paid subscription
	ProTier SubscriptionTier = "pro"
)

// TierLimits defines the repository limits for each tier
var TierLimits = map[SubscriptionTier]int{
	FreeTier: 0,  // Free tier: 2 repositories
	ProTier:  10, // Pro tier: 10 repositories
}

// Store abstracts the database operations used by the application.
// This allows injecting a mock implementation in tests.
type Store interface {
	GetUserProfile(userID string) (*UserProfile, error)
	GetRepoLimit(userID string) (int, error)
	ListRepositories(userID string) ([]Repository, error)
	GetRepository(userID, repoName string) (*Repository, error)
	GetRepositoryByID(repoID string) (*Repository, error)
	AddRepository(userID, repoName, webhookSecret string) (*Repository, error)
	DeleteRepository(userID, repoName string) error
	DeleteRepositoryByID(repoID string) error

	// Subscription management
	UpdateUserSubscription(userID string, tier SubscriptionTier) error
	UpdateUserStripeInfo(userID, customerID, subscriptionID string, status string) error

	// GitHub event persistence methods
	SaveGitHubEvent(event *GitHubEvent) error
	GetUndeliveredEvents(userID string) ([]GitHubEvent, error)
	GetUndeliveredEventsByRepo(userID, repoID string) ([]GitHubEvent, error)
	GetRecentEventIDs(userID string, limit int) ([]string, error)
	GetRecentEventIDsByRepo(userID, repoID string, limit int) ([]string, error)
	GetEventByID(eventID string) (*GitHubEvent, error)
	MarkEventAsDelivered(eventID string) error
	DeleteExpiredEvents() error
}

// Client handles Supabase database operations
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	log        zerolog.Logger
}

// Repository represents a tracked GitHub repository
type Repository struct {
	ID            string `json:"id,omitempty"`
	UserID        string `json:"user_id"`
	RepoName      string `json:"repo_name"`
	WebhookSecret string `json:"webhook_secret"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// GitHubEvent represents a persisted GitHub webhook event
type GitHubEvent struct {
	ID            string          `json:"id"`
	UserID        string          `json:"user_id"`
	RepoID        string          `json:"repo_id"`
	RepoName      string          `json:"repo_name"`
	EventType     string          `json:"event_type"`
	Payload       json.RawMessage `json:"payload"` // Raw webhook payload (jsonb)
	CommitMessage string          `json:"commit_message,omitempty"`
	CreatedAt     string          `json:"created_at,omitempty"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
	IsDelivered   bool            `json:"is_delivered"`
}

// UserProfile represents a user profile with subscription information
// Note: supports schemas where the user UUID is stored in either `id` or `uuid` column.
type UserProfile struct {
	ID          string `json:"id"`
	UUID        string `json:"uuid"`
	Email       string `json:"email"`
	AccountType string `json:"account_type"`
	RepoLimit   int    `json:"repo_limit"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	// Back-compat: if your table uses `tier` string field, map it to SubscriptionTier
	Tier SubscriptionTier `json:"tier"`
}

// NewClient creates a new Supabase client
func NewClient(baseURL, apiKey string) (*Client, error) {
	// Validate URL
	_, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Supabase URL: %w", err)
	}

	return &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		log:        logger.Logger(map[string]interface{}{"component": "database"}),
	}, nil
}

// request makes an HTTP request to the Supabase REST API
func (c *Client) request(method, path string, body interface{}, result interface{}) error {
	urlStr := fmt.Sprintf("%s/rest/v1/%s", c.baseURL, path)

	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("apikey", c.apiKey)
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Debug logging for API key issues
	if c.apiKey == "" {
		c.log.Error().Msg("API key is empty - this will cause authentication failures")
	} else {
		prefixLen := 10
		if len(c.apiKey) < prefixLen {
			prefixLen = len(c.apiKey)
		}
		c.log.Debug().
			Str("api_key_prefix", c.apiKey[:prefixLen]).
			Msg("Using API key (prefix shown)")
	}

	// Add Prefer header for POST requests to get back the inserted row
	if method == http.MethodPost {
		req.Header.Set("Prefer", "return=representation")
	}

	c.log.Debug().
		Str("method", method).
		Str("path", path).
		Msg("Making Supabase API request")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check for error status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response if result container was provided
	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// GetUserProfile retrieves a user profile by user ID (JWT sub).
// It filters by `id`, which should match auth.users(id).
func (c *Client) GetUserProfile(userID string) (*UserProfile, error) {
	path := fmt.Sprintf("profiles?id=eq.%s", url.QueryEscape(userID))
	c.log.Info().
		Str("user_id", userID).
		Str("path", path).
		Msg("GetUserProfile: querying profiles by id")
	var profiles []UserProfile
	if err := c.request(http.MethodGet, path, nil, &profiles); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Msg("GetUserProfile: request failed")
		return nil, err
	}
	if len(profiles) == 0 {
		c.log.Warn().
			Str("user_id", userID).
			Msg("GetUserProfile: no profile found")
		return nil, errors.New("user profile not found")
	}
	c.log.Info().
		Str("user_id", userID).
		Msg("GetUserProfile: profile found")
	return &profiles[0], nil
}

// GetRepoLimit returns the repository limit for a user based on their profile
func (c *Client) GetRepoLimit(userID string) (int, error) {
	c.log.Info().
		Str("user_id", userID).
		Msg("GetRepoLimit: start")
	profile, err := c.GetUserProfile(userID)
	if err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Msg("GetRepoLimit: failed to load profile")
		return 0, fmt.Errorf("failed to get user profile: %w", err)
	}

	// 1) If explicit repo_limit is set, prefer it
	if profile.RepoLimit > 0 {
		c.log.Info().
			Str("user_id", userID).
			Int("repo_limit", profile.RepoLimit).
			Msg("GetRepoLimit: using profile.repo_limit")
		return profile.RepoLimit, nil
	}

	// 2) If account_type provided, map to tier limits
	if profile.AccountType != "" {
		if limit, ok := TierLimits[SubscriptionTier(profile.AccountType)]; ok {
			c.log.Info().
				Str("user_id", userID).
				Str("account_type", profile.AccountType).
				Int("limit", limit).
				Msg("GetRepoLimit: using account_type tier mapping")
			return limit, nil
		}
	}

	// 3) Back-compat: if profile has a `tier` field
	if profile.Tier != "" {
		if limit, ok := TierLimits[profile.Tier]; ok {
			c.log.Info().
				Str("user_id", userID).
				Str("tier", string(profile.Tier)).
				Int("limit", limit).
				Msg("GetRepoLimit: using legacy tier mapping")
			return limit, nil
		}
	}

	// Default to free tier
	c.log.Warn().
		Str("user_id", userID).
		Int("limit", TierLimits[FreeTier]).
		Msg("GetRepoLimit: defaulting to FreeTier")
	return TierLimits[FreeTier], nil
}

// ListRepositories retrieves all repositories for a user
func (c *Client) ListRepositories(userID string) ([]Repository, error) {
	path := fmt.Sprintf("repos?user_id=eq.%s", url.QueryEscape(userID))

	var repos []Repository
	if err := c.request(http.MethodGet, path, nil, &repos); err != nil {
		return nil, err
	}

	return repos, nil
}

// GetRepository retrieves a specific repository by name
func (c *Client) GetRepository(userID, repoName string) (*Repository, error) {
	path := fmt.Sprintf("repos?user_id=eq.%s&repo_name=eq.%s",
		url.QueryEscape(userID), url.QueryEscape(repoName))

	var repos []Repository
	if err := c.request(http.MethodGet, path, nil, &repos); err != nil {
		return nil, err
	}

	if len(repos) == 0 {
		return nil, ErrRepositoryNotFound
	}

	return &repos[0], nil
}

// GetRepositoryByID retrieves a repository by its ID
func (c *Client) GetRepositoryByID(repoID string) (*Repository, error) {
	path := fmt.Sprintf("repos?id=eq.%s", url.QueryEscape(repoID))

	var repos []Repository
	if err := c.request(http.MethodGet, path, nil, &repos); err != nil {
		return nil, err
	}

	if len(repos) == 0 {
		return nil, ErrRepositoryNotFound
	}

	return &repos[0], nil
}

// AddRepository adds a new tracked repository for a user
func (c *Client) AddRepository(userID, repoName, webhookSecret string) (*Repository, error) {
	c.log.Info().
		Str("user_id", userID).
		Str("repo_name", repoName).
		Msg("AddRepository: start")
	// First check if the repository already exists
	existingRepo, err := c.GetRepository(userID, repoName)
	if err == nil && existingRepo != nil {
		c.log.Warn().
			Str("user_id", userID).
			Str("repo_name", repoName).
			Msg("AddRepository: repository already exists")
		return nil, ErrRepoAlreadyExists
	}

	// Get the user's repo limit based on their subscription
	limit, err := c.GetRepoLimit(userID)
	if err != nil {
		return nil, err
	}
	c.log.Info().
		Str("user_id", userID).
		Int("repo_limit", limit).
		Msg("AddRepository: repo limit")

	// Count existing repositories
	repos, err := c.ListRepositories(userID)
	if err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Msg("AddRepository: failed to list repositories")
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	c.log.Info().
		Str("user_id", userID).
		Int("current_count", len(repos)).
		Msg("AddRepository: current repository count")

	if len(repos) >= limit {
		c.log.Warn().
			Str("user_id", userID).
			Int("limit", limit).
			Int("count", len(repos)).
			Msg("AddRepository: user reached repository limit")
		return nil, ErrRepoLimitReached
	}

	// Insert repository
	repo := Repository{
		UserID:        userID,
		RepoName:      repoName,
		WebhookSecret: webhookSecret,
	}
	var result []Repository
	if err := c.request(http.MethodPost, "repos", repo, &result); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("repo_name", repoName).
			Msg("AddRepository: insert failed")
		return nil, fmt.Errorf("failed to insert repository: %w", err)
	}
	if len(result) == 0 {
		c.log.Error().
			Str("user_id", userID).
			Str("repo_name", repoName).
			Msg("AddRepository: insert returned no rows")
		return nil, errors.New("no repository returned after insertion")
	}
	c.log.Info().
		Str("user_id", userID).
		Str("repo_name", repoName).
		Str("repo_id", result[0].ID).
		Msg("AddRepository: success")
	return &result[0], nil
}

// DeleteRepository removes a repository from tracking
func (c *Client) DeleteRepository(userID, repoName string) error {
	c.log.Info().
		Str("user_id", userID).
		Str("repo_name", repoName).
		Msg("DeleteRepository: start")

	repo, err := c.GetRepository(userID, repoName)
	if err != nil {
		c.log.Warn().
			Err(err).
			Str("user_id", userID).
			Str("repo_name", repoName).
			Msg("DeleteRepository: repo not found")
		return ErrRepositoryNotFound
	}

	path := fmt.Sprintf("repos?id=eq.%s", url.QueryEscape(repo.ID))
	if err := c.request(http.MethodDelete, path, nil, nil); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("repo_name", repoName).
			Msg("DeleteRepository: delete failed")
		return fmt.Errorf("failed to delete repository: %w", err)
	}

	c.log.Info().
		Str("user_id", userID).
		Str("repo_name", repoName).
		Msg("DeleteRepository: success")
	return nil
}

// DeleteRepositoryByID removes a repository from tracking by its ID
func (c *Client) DeleteRepositoryByID(repoID string) error {
	c.log.Info().
		Str("repo_id", repoID).
		Msg("DeleteRepositoryByID: start")

	repo, err := c.GetRepositoryByID(repoID)
	if err != nil {
		c.log.Warn().
			Err(err).
			Str("repo_id", repoID).
			Msg("DeleteRepositoryByID: repo not found")
		return ErrRepositoryNotFound
	}

	path := fmt.Sprintf("repos?id=eq.%s", url.QueryEscape(repo.ID))
	if err := c.request(http.MethodDelete, path, nil, nil); err != nil {
		c.log.Error().
			Err(err).
			Str("repo_id", repoID).
			Msg("DeleteRepositoryByID: delete failed")
		return fmt.Errorf("failed to delete repository: %w", err)
	}

	c.log.Info().
		Str("repo_id", repoID).
		Msg("DeleteRepositoryByID: success")
	return nil
}

// SaveGitHubEvent inserts or updates a GitHub event
func (c *Client) SaveGitHubEvent(event *GitHubEvent) error {
	c.log.Info().
		Str("user_id", event.UserID).
		Str("repo_name", event.RepoName).
		Str("event_type", event.EventType).
		Msg("SaveGitHubEvent: start")

	// Generate a UUID if the event ID is empty
	if event.ID == "" {
		event.ID = uuid.New().String()
		c.log.Debug().
			Str("event_id", event.ID).
			Msg("Generated new UUID for GitHub event")
	}

	// Try to insert first - this is the most common case and fastest
	c.log.Info().
		Str("event_id", event.ID).
		Msg("SaveGitHubEvent: attempting insert")

	// Log the event data being sent for debugging
	c.log.Debug().
		Str("event_id", event.ID).
		Str("user_id", event.UserID).
		Str("repo_id", event.RepoID).
		Str("repo_name", event.RepoName).
		Str("event_type", event.EventType).
		Bool("is_delivered", event.IsDelivered).
		Str("expires_at", event.ExpiresAt).
		Str("commit_message", event.CommitMessage).
		Msg("SaveGitHubEvent: event data being sent")

	path := "github_events"
	if err := c.request(http.MethodPost, path, event, nil); err != nil {
		// If insert fails, it might be due to a duplicate key constraint
		// Try to update instead
		c.log.Warn().
			Err(err).
			Str("event_id", event.ID).
			Str("user_id", event.UserID).
			Str("repo_name", event.RepoName).
			Str("event_type", event.EventType).
			Msg("SaveGitHubEvent: insert failed, attempting update")

		// Try to update the existing event
		updatePath := fmt.Sprintf("github_events?id=eq.%s", url.QueryEscape(event.ID))
		if updateErr := c.request(http.MethodPatch, updatePath, event, nil); updateErr != nil {
			c.log.Error().
				Err(updateErr).
				Str("event_id", event.ID).
				Str("user_id", event.UserID).
				Str("repo_name", event.RepoName).
				Str("event_type", event.EventType).
				Msg("SaveGitHubEvent: both insert and update failed")
			return fmt.Errorf("failed to save event (insert: %v, update: %v)", err, updateErr)
		}

		c.log.Info().
			Str("event_id", event.ID).
			Msg("SaveGitHubEvent: update succeeded")
	} else {
		c.log.Info().
			Str("event_id", event.ID).
			Msg("SaveGitHubEvent: insert succeeded")
	}

	c.log.Info().
		Str("event_id", event.ID).
		Msg("SaveGitHubEvent: success")
	return nil
}

// GetUndeliveredEvents retrieves undelivered GitHub events for a user
func (c *Client) GetUndeliveredEvents(userID string) ([]GitHubEvent, error) {
	path := fmt.Sprintf("github_events?user_id=eq.%s&is_delivered=eq.false",
		url.QueryEscape(userID))

	var events []GitHubEvent
	if err := c.request(http.MethodGet, path, nil, &events); err != nil {
		return nil, err
	}

	return events, nil
}

// GetUndeliveredEventsByRepo retrieves undelivered GitHub events for a user filtered by repo_id
func (c *Client) GetUndeliveredEventsByRepo(userID, repoID string) ([]GitHubEvent, error) {
	path := fmt.Sprintf("github_events?user_id=eq.%s&repo_id=eq.%s&is_delivered=eq.false",
		url.QueryEscape(userID), url.QueryEscape(repoID))

	var events []GitHubEvent
	if err := c.request(http.MethodGet, path, nil, &events); err != nil {
		return nil, err
	}

	return events, nil
}

// GetRecentEventIDs retrieves the IDs of the most recent undelivered events for a user
func (c *Client) GetRecentEventIDs(userID string, limit int) ([]string, error) {
	// First, let's try to get ALL events for this user to debug
	debugPath := fmt.Sprintf("github_events?user_id=eq.%s&select=id,is_delivered,created_at&order=created_at.desc",
		url.QueryEscape(userID))

	c.log.Info().
		Str("user_id", userID).
		Str("debug_path", debugPath).
		Msg("GetRecentEventIDs: Debug query - getting all events for user")

	var debugResult []struct {
		ID          string `json:"id"`
		IsDelivered bool   `json:"is_delivered"`
		CreatedAt   string `json:"created_at"`
	}
	if err := c.request(http.MethodGet, debugPath, nil, &debugResult); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Msg("GetRecentEventIDs: Debug query failed")
		return nil, err
	}

	c.log.Info().
		Str("user_id", userID).
		Int("total_events", len(debugResult)).
		Interface("events", debugResult).
		Msg("GetRecentEventIDs: Debug - found events for user")

	// Now do the original query
	path := fmt.Sprintf("github_events?user_id=eq.%s&is_delivered=eq.false&select=id&order=created_at.desc&limit=%d",
		url.QueryEscape(userID), limit)

	c.log.Info().
		Str("user_id", userID).
		Str("path", path).
		Msg("GetRecentEventIDs: Original query")

	var result []struct {
		ID string `json:"id"`
	}
	if err := c.request(http.MethodGet, path, nil, &result); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Msg("GetRecentEventIDs: Original query failed")
		return nil, err
	}

	// Extract IDs from the result
	var ids []string
	for _, r := range result {
		ids = append(ids, r.ID)
	}

	c.log.Info().
		Str("user_id", userID).
		Int("undelivered_count", len(ids)).
		Strs("event_ids", ids).
		Msg("GetRecentEventIDs: Found undelivered events")

	return ids, nil
}

// GetRecentEventIDsByRepo retrieves the IDs of the most recent undelivered events for a user filtered by repo_id
func (c *Client) GetRecentEventIDsByRepo(userID, repoID string, limit int) ([]string, error) {
	path := fmt.Sprintf("github_events?user_id=eq.%s&repo_id=eq.%s&is_delivered=eq.false&select=id&order=created_at.desc&limit=%d",
		url.QueryEscape(userID), url.QueryEscape(repoID), limit)

	var result []struct {
		ID string `json:"id"`
	}
	if err := c.request(http.MethodGet, path, nil, &result); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("repo_id", repoID).
			Msg("GetRecentEventIDsByRepo: Query failed")
		return nil, err
	}

	// Extract IDs from the result
	var ids []string
	for _, r := range result {
		ids = append(ids, r.ID)
	}

	c.log.Info().
		Str("user_id", userID).
		Str("repo_id", repoID).
		Int("undelivered_count", len(ids)).
		Strs("event_ids", ids).
		Msg("GetRecentEventIDsByRepo: Found undelivered events for repo")

	return ids, nil
}

// GetEventByID retrieves a GitHub event by its ID
func (c *Client) GetEventByID(eventID string) (*GitHubEvent, error) {
	if eventID == "" {
		return nil, nil
	}

	path := fmt.Sprintf("github_events?id=eq.%s", url.QueryEscape(eventID))

	var events []GitHubEvent
	if err := c.request(http.MethodGet, path, nil, &events); err != nil {
		return nil, err
	}

	if len(events) == 0 {
		return nil, nil
	}

	return &events[0], nil
}

// MarkEventAsDelivered marks a GitHub event as delivered
func (c *Client) MarkEventAsDelivered(eventID string) error {
	c.log.Info().
		Str("event_id", eventID).
		Msg("MarkEventAsDelivered: start")

	// Update the event to set is_delivered = true
	path := fmt.Sprintf("github_events?id=eq.%s", url.QueryEscape(eventID))
	if err := c.request(http.MethodPatch, path, map[string]interface{}{
		"is_delivered": true,
	}, nil); err != nil {
		c.log.Error().
			Err(err).
			Str("event_id", eventID).
			Msg("MarkEventAsDelivered: update failed")
		return fmt.Errorf("failed to mark event as delivered: %w", err)
	}

	c.log.Info().
		Str("event_id", eventID).
		Msg("MarkEventAsDelivered: success")
	return nil
}

// DeleteExpiredEvents removes expired GitHub events
func (c *Client) DeleteExpiredEvents() error {
	c.log.Info().
		Msg("DeleteExpiredEvents: start")

	// Delete events where expires_at < now()
	path := "github_events"
	if err := c.request(http.MethodDelete, path, map[string]interface{}{
		"expires_at": map[string]interface{}{
			"lt": time.Now().Format(time.RFC3339),
		},
	}, nil); err != nil {
		c.log.Error().
			Err(err).
			Msg("DeleteExpiredEvents: delete failed")
		return fmt.Errorf("failed to delete expired events: %w", err)
	}

	c.log.Info().
		Msg("DeleteExpiredEvents: success")
	return nil
}

// UpdateUserSubscription updates a user's subscription tier
func (c *Client) UpdateUserSubscription(userID string, tier SubscriptionTier) error {
	c.log.Info().
		Str("user_id", userID).
		Str("tier", string(tier)).
		Msg("UpdateUserSubscription: start")

	// Update the user's account_type to the new tier
	path := fmt.Sprintf("profiles?id=eq.%s", url.QueryEscape(userID))
	updateData := map[string]interface{}{
		"account_type": string(tier),
	}

	if err := c.request(http.MethodPatch, path, updateData, nil); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("tier", string(tier)).
			Msg("UpdateUserSubscription: update failed")
		return fmt.Errorf("failed to update user subscription: %w", err)
	}

	c.log.Info().
		Str("user_id", userID).
		Str("tier", string(tier)).
		Msg("UpdateUserSubscription: success")
	return nil
}

// UpdateUserStripeInfo updates a user's Stripe customer and subscription information
func (c *Client) UpdateUserStripeInfo(userID, customerID, subscriptionID, status string) error {
	c.log.Info().
		Str("user_id", userID).
		Str("customer_id", customerID).
		Str("subscription_id", subscriptionID).
		Str("status", status).
		Msg("UpdateUserStripeInfo: start")

	// Update the user's Stripe information
	path := fmt.Sprintf("profiles?id=eq.%s", url.QueryEscape(userID))
	updateData := map[string]interface{}{
		"stripe_customer_id":  customerID,
		"subscription_status": status,
	}

	if err := c.request(http.MethodPatch, path, updateData, nil); err != nil {
		c.log.Error().
			Err(err).
			Str("user_id", userID).
			Str("customer_id", customerID).
			Str("subscription_id", subscriptionID).
			Msg("UpdateUserStripeInfo: update failed")
		return fmt.Errorf("failed to update user Stripe info: %w", err)
	}

	c.log.Info().
		Str("user_id", userID).
		Str("customer_id", customerID).
		Str("subscription_id", subscriptionID).
		Str("status", status).
		Msg("UpdateUserStripeInfo: success")
	return nil
}
