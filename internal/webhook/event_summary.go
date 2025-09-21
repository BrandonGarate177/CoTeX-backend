package webhook

import (
	"encoding/json"
	"fmt"
	"time"
)

// EventSummary represents a clean, UI-friendly summary of a GitHub event
type EventSummary struct {
	ID          string            `json:"id"`           // X-GitHub-Delivery GUID
	Type        string            `json:"type"`         // push, pull_request, issues, etc.
	Repo        string            `json:"repo"`         // owner/repo
	Branch      string            `json:"branch"`       // branch name (for push events)
	Actor       string            `json:"actor"`        // username who triggered the event
	Timestamp   string            `json:"timestamp"`    // ISO 8601 timestamp
	Headline    string            `json:"headline"`     // Human-readable summary
	Files       []FileChange      `json:"files"`        // List of changed files
	CommitCount int               `json:"commit_count"` // Number of commits (for push events)
	CommitSHAs  []string          `json:"commit_shas"`  // List of commit SHAs
	Metadata    map[string]string `json:"metadata"`     // Additional event-specific data
}

// FileChange represents a file change in a commit
type FileChange struct {
	Path   string `json:"path"`   // File path
	Change string `json:"change"` // added, modified, removed, renamed
	Commit string `json:"commit"` // Commit SHA
}

// GitHubWebhookPayload represents the structure of GitHub webhook payloads
type GitHubWebhookPayload struct {
	Ref        string `json:"ref"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
	Commits []struct {
		ID       string   `json:"id"`
		Message  string   `json:"message"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"commits"`
	PullRequest *struct {
		Title string `json:"title"`
		State string `json:"state"`
		Head  struct {
			Ref string `json:"ref"`
		} `json:"head"`
	} `json:"pull_request"`
	Issue *struct {
		Title string `json:"title"`
		State string `json:"state"`
	} `json:"issue"`
	Action string `json:"action"`
}

// ParseGitHubWebhook parses a GitHub webhook payload and creates an event summary
func ParseGitHubWebhook(deliveryID, eventType string, payload []byte) (*EventSummary, error) {
	var webhookPayload GitHubWebhookPayload
	if err := json.Unmarshal(payload, &webhookPayload); err != nil {
		return nil, err
	}

	summary := &EventSummary{
		ID:        deliveryID,
		Type:      eventType,
		Repo:      webhookPayload.Repository.FullName,
		Actor:     webhookPayload.Sender.Login,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Files:     []FileChange{},
		Metadata:  make(map[string]string),
	}

	// Parse based on event type
	switch eventType {
	case "push":
		summary = parsePushEvent(summary, &webhookPayload)
	case "pull_request":
		summary = parsePullRequestEvent(summary, &webhookPayload)
	case "issues":
		summary = parseIssueEvent(summary, &webhookPayload)
	default:
		summary.Headline = generateGenericHeadline(eventType, webhookPayload.Action)
	}

	return summary, nil
}

func parsePushEvent(summary *EventSummary, payload *GitHubWebhookPayload) *EventSummary {
	// Extract branch name from ref (e.g., "refs/heads/main" -> "main")
	if len(payload.Ref) > 11 && payload.Ref[:11] == "refs/heads/" {
		summary.Branch = payload.Ref[11:]
	}

	// Process commits
	summary.CommitCount = len(payload.Commits)
	summary.CommitSHAs = make([]string, 0, len(payload.Commits))

	fileChanges := make(map[string]FileChange)

	for _, commit := range payload.Commits {
		summary.CommitSHAs = append(summary.CommitSHAs, commit.ID)

		// Track file changes
		for _, file := range commit.Added {
			fileChanges[file] = FileChange{
				Path:   file,
				Change: "added",
				Commit: commit.ID,
			}
		}
		for _, file := range commit.Modified {
			fileChanges[file] = FileChange{
				Path:   file,
				Change: "modified",
				Commit: commit.ID,
			}
		}
		for _, file := range commit.Removed {
			fileChanges[file] = FileChange{
				Path:   file,
				Change: "removed",
				Commit: commit.ID,
			}
		}
	}

	// Convert map to slice
	summary.Files = make([]FileChange, 0, len(fileChanges))
	for _, change := range fileChanges {
		summary.Files = append(summary.Files, change)
	}

	// Generate headline
	if summary.CommitCount == 1 {
		summary.Headline = "1 commit pushed to " + summary.Branch
	} else {
		summary.Headline = fmt.Sprintf("%d commits pushed to %s", summary.CommitCount, summary.Branch)
	}

	return summary
}

func parsePullRequestEvent(summary *EventSummary, payload *GitHubWebhookPayload) *EventSummary {
	if payload.PullRequest != nil {
		summary.Branch = payload.PullRequest.Head.Ref
		summary.Headline = fmt.Sprintf("Pull request %s: %s", payload.Action, payload.PullRequest.Title)
		summary.Metadata["pr_state"] = payload.PullRequest.State
		summary.Metadata["pr_title"] = payload.PullRequest.Title
	}
	return summary
}

func parseIssueEvent(summary *EventSummary, payload *GitHubWebhookPayload) *EventSummary {
	if payload.Issue != nil {
		summary.Headline = fmt.Sprintf("Issue %s: %s", payload.Action, payload.Issue.Title)
		summary.Metadata["issue_state"] = payload.Issue.State
		summary.Metadata["issue_title"] = payload.Issue.Title
	}
	return summary
}

func generateGenericHeadline(eventType, action string) string {
	if action != "" {
		return fmt.Sprintf("%s %s", eventType, action)
	}
	return eventType
}
