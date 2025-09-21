// Package webhook provides WebSocket communication functionality
package webhook

import (
	"time"
)

// MessageType defines the type of WebSocket messages
type MessageType string

const (
	// MessageTypeGithubEvent represents a GitHub webhook event
	MessageTypeGithubEvent MessageType = "github_event"

	// MessageTypeClientEvent represents a message from client
	MessageTypeClientEvent MessageType = "client_event"

	// MessageTypeSystemEvent represents a system event message
	MessageTypeSystemEvent MessageType = "system_event"

	// MessageTypeError represents an error message
	MessageTypeError MessageType = "error"
)

// Message represents a message sent through WebSocket
type Message struct {
	// Type of the message
	Type MessageType `json:"type"`

	// User ID of the message sender
	UserID string `json:"user_id,omitempty"`

	// Target User ID for directed messages (used internally)
	TargetUserID string `json:"target_user_id,omitempty"`

	// Repository name the message relates to
	RepoName string `json:"repo_name,omitempty"`

	// Event name (for GitHub webhook events)
	Event string `json:"event,omitempty"`

	// Payload contains the actual message data
	Payload interface{} `json:"payload"`

	// Timestamp of the message
	Timestamp time.Time `json:"timestamp"`
}

// NewGithubEventMessage creates a new GitHub webhook event message
func NewGithubEventMessage(userID, repoName, eventName string, payload interface{}) *Message {
	return &Message{
		Type:      MessageTypeGithubEvent,
		UserID:    userID,
		RepoName:  repoName,
		Event:     eventName,
		Payload:   payload,
		Timestamp: time.Now(),
	}
}

// NewSystemMessage creates a new system event message
func NewSystemMessage(message string) *Message {
	return &Message{
		Type:      MessageTypeSystemEvent,
		Payload:   message,
		Timestamp: time.Now(),
	}
}

// NewErrorMessage creates a new error message
func NewErrorMessage(userID string, err error) *Message {
	return &Message{
		Type:      MessageTypeError,
		UserID:    userID,
		Payload:   err.Error(),
		Timestamp: time.Now(),
	}
}
