package websocket

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/webhook"
)

type mockRepoGetter struct {
	repo *database.Repository
	err  error
}

func (m *mockRepoGetter) GetRepositoryByID(repoID string) (*database.Repository, error) {
	return m.repo, m.err
}

type mockBroadcaster struct {
	calls []struct {
		user string
		msg  *webhook.Message
	}
}

func (m *mockBroadcaster) BroadcastToUser(userID string, message *webhook.Message) {
	m.calls = append(m.calls, struct {
		user string
		msg  *webhook.Message
	}{user: userID, msg: message})
}

func sign(body []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func TestGitHubHandler_ValidSignature_Broadcasts(t *testing.T) {
	secret := "shhh"
	repo := &database.Repository{ID: "r1", UserID: "u1", RepoName: "octo/repo", WebhookSecret: secret}
	db := &mockRepoGetter{repo: repo}
	b := &mockBroadcaster{}
	h := NewGitHubHandler(db, b)

	payload := map[string]any{
		"repository": map[string]any{
			"name":      "repo",
			"full_name": "octo/repo",
			"html_url":  "https://github.com/octo/repo",
		},
	}
	data, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/github/r1", bytes.NewReader(data))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", sign(data, secret))
	rec := httptest.NewRecorder()

	h.HandleWebhook(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if len(b.calls) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(b.calls))
	}
	if b.calls[0].user != "u1" {
		t.Fatalf("unexpected user: %s", b.calls[0].user)
	}
	if b.calls[0].msg.Type != webhook.MessageTypeGithubEvent {
		t.Fatalf("unexpected message type: %s", b.calls[0].msg.Type)
	}
}

func TestGitHubHandler_InvalidSignature_NoBroadcast(t *testing.T) {
	secret := "shhh"
	repo := &database.Repository{ID: "r1", UserID: "u1", RepoName: "octo/repo", WebhookSecret: secret}
	db := &mockRepoGetter{repo: repo}
	b := &mockBroadcaster{}
	h := NewGitHubHandler(db, b)

	data := []byte(`{"repository":{"full_name":"octo/repo"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/github/r1", bytes.NewReader(data))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", "sha256=badsignature")
	rec := httptest.NewRecorder()

	h.HandleWebhook(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if len(b.calls) != 0 {
		t.Fatalf("expected 0 broadcasts, got %d", len(b.calls))
	}
}

func TestGitHubHandler_MissingHeaders_BadRequest(t *testing.T) {
	repo := &database.Repository{ID: "r1", UserID: "u1", RepoName: "octo/repo", WebhookSecret: "shhh"}
	db := &mockRepoGetter{repo: repo}
	b := &mockBroadcaster{}
	h := NewGitHubHandler(db, b)

	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/github/r1", bytes.NewReader([]byte("{}")))
	rec := httptest.NewRecorder()
	h.HandleWebhook(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
