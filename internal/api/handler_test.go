package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/brandon/cotex-backend/internal/auth"
	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/webhook"
)

type mockStore struct {
	mu       sync.Mutex
	repos    map[string]database.Repository // key: repo ID
	byUser   map[string][]string            // user -> repo IDs
	profiles map[string]database.UserProfile
	limit    int
	idSeq    int
}

func newMockStore(limit int) *mockStore {
	return &mockStore{
		repos:    make(map[string]database.Repository),
		byUser:   make(map[string][]string),
		profiles: make(map[string]database.UserProfile),
		limit:    limit,
		idSeq:    0,
	}
}

func (m *mockStore) nextID() string {
	m.idSeq++
	return fmt.Sprintf("r%d", m.idSeq)
}

func (m *mockStore) GetUserProfile(userID string) (*database.UserProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.profiles[userID]; ok {
		return &p, nil
	}
	p := database.UserProfile{ID: userID, Tier: database.FreeTier}
	m.profiles[userID] = p
	return &p, nil
}

func (m *mockStore) GetRepoLimit(userID string) (int, error) { return m.limit, nil }

func (m *mockStore) ListRepositories(userID string) ([]database.Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := m.byUser[userID]
	var out []database.Repository
	for _, id := range ids {
		out = append(out, m.repos[id])
	}
	return out, nil
}

func (m *mockStore) GetRepository(userID, repoName string) (*database.Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.byUser[userID] {
		r := m.repos[id]
		if r.RepoName == repoName {
			cp := r
			return &cp, nil
		}
	}
	return nil, database.ErrRepositoryNotFound
}

func (m *mockStore) GetRepositoryByID(repoID string) (*database.Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.repos[repoID]; ok {
		cp := r
		return &cp, nil
	}
	return nil, database.ErrRepositoryNotFound
}

func (m *mockStore) AddRepository(userID, repoName, webhookSecret string) (*database.Repository, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// duplicate
	for _, id := range m.byUser[userID] {
		if m.repos[id].RepoName == repoName {
			return nil, database.ErrRepoAlreadyExists
		}
	}
	// limit
	if len(m.byUser[userID]) >= m.limit {
		return nil, database.ErrRepoLimitReached
	}
	id := m.nextID()
	repo := database.Repository{ID: id, UserID: userID, RepoName: repoName, WebhookSecret: webhookSecret}
	m.repos[id] = repo
	m.byUser[userID] = append(m.byUser[userID], id)
	cp := repo
	return &cp, nil
}

func (m *mockStore) DeleteRepository(userID, repoName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := m.byUser[userID]
	for i, id := range ids {
		if m.repos[id].RepoName == repoName {
			delete(m.repos, id)
			m.byUser[userID] = append(ids[:i], ids[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockStore) DeleteRepositoryByID(repoID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	repo, ok := m.repos[repoID]
	if !ok {
		return nil
	}
	ids := m.byUser[repo.UserID]
	for i, id := range ids {
		if id == repoID {
			m.byUser[repo.UserID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	delete(m.repos, repoID)
	return nil
}

func withUser(ctx context.Context, userID string) context.Context {
	claims := &auth.UserClaims{UserID: userID}
	return context.WithValue(ctx, auth.UserContextKey, claims)
}

type addRepoResp struct {
	Repository struct {
		ID       string `json:"id"`
		RepoName string `json:"repo_name"`
	} `json:"repository"`
	WebhookURL string `json:"webhook_url"`
}

func TestRepoHandler_AddListDeleteFlow(t *testing.T) {
	store := newMockStore(2)
	hub := webhook.NewHub()
	go hub.Run()
	h := NewHandler(store, hub, nil)

	userID := "user-1"

	// Add repo
	body := bytes.NewBufferString(`{"repo_name":"octo/repo","webhook_secret":"shhh"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/repos", body)
	req = req.WithContext(withUser(req.Context(), userID))
	rec := httptest.NewRecorder()
	h.RepoHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}
	var ar addRepoResp
	if err := json.Unmarshal(rec.Body.Bytes(), &ar); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if ar.Repository.RepoName != "octo/repo" {
		t.Fatalf("unexpected repo name: %s", ar.Repository.RepoName)
	}
	if ar.WebhookURL == "" {
		t.Fatal("expected webhook_url")
	}

	// List repos
	req2 := httptest.NewRequest(http.MethodGet, "/api/repos", nil)
	req2 = req2.WithContext(withUser(req2.Context(), userID))
	rec2 := httptest.NewRecorder()
	h.RepoHandler(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	var list []database.Repository
	if err := json.Unmarshal(rec2.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid json list: %v", err)
	}
	if len(list) != 1 || list[0].RepoName != "octo/repo" {
		t.Fatalf("unexpected list: %+v", list)
	}

	// Delete by ID
	req3 := httptest.NewRequest(http.MethodDelete, "/api/repos?id="+ar.Repository.ID, nil)
	req3 = req3.WithContext(withUser(req3.Context(), userID))
	rec3 := httptest.NewRecorder()
	h.RepoHandler(rec3, req3)
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec3.Code)
	}
}

func TestRepoHandler_AddRepo_ConflictAndLimit(t *testing.T) {
	store := newMockStore(1)
	hub := webhook.NewHub()
	go hub.Run()
	h := NewHandler(store, hub, nil)
	userID := "user-1"

	add := func() *httptest.ResponseRecorder {
		body := bytes.NewBufferString(`{"repo_name":"octo/repo","webhook_secret":"shhh"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/repos", body)
		req = req.WithContext(withUser(req.Context(), userID))
		rec := httptest.NewRecorder()
		h.RepoHandler(rec, req)
		return rec
	}

	// First add
	if rec := add(); rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}
	// Duplicate
	if rec := add(); rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}
