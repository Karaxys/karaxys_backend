package ingest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"karaxys_backend/internal/contracts"
	"karaxys_backend/internal/core"
)

func TestHandleConversationAcceptsValidConversation(t *testing.T) {
	store := &fakeStore{}
	analyzer := &fakeAnalyzer{}
	service := NewService(store, analyzer, "agent-token")

	body := loadExample(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.logs) != 1 {
		t.Fatalf("expected one saved log, got %d", len(store.logs))
	}
	if analyzer.count != 1 {
		t.Fatalf("expected analyzer to run once, got %d", analyzer.count)
	}

	saved := store.logs[0]
	if saved.SchemaVersion != contracts.SchemaHTTPConversationV1 {
		t.Fatalf("unexpected schema version: %s", saved.SchemaVersion)
	}
	if saved.CaptureSource != "ebpf" || saved.CaptureMode != "container" || saved.AgentID != "agent-linux-01" {
		t.Fatalf("unexpected capture metadata: source=%s mode=%s agent=%s", saved.CaptureSource, saved.CaptureMode, saved.AgentID)
	}
	if saved.Method != http.MethodGet || saved.Host != "api.example.local" || saved.Path != "/api/v1/users" {
		t.Fatalf("unexpected request mapping: %+v", saved)
	}

	var response Response
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "accepted" || response.SchemaVersion != contracts.SchemaHTTPConversationV1 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestHandleConversationRejectsMissingToken(t *testing.T) {
	service := NewService(&fakeStore{}, nil, "agent-token")
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleConversationRejectsDisabledIngestion(t *testing.T) {
	service := NewService(&fakeStore{}, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleConversationRejectsInvalidContract(t *testing.T) {
	service := NewService(&fakeStore{}, nil, "agent-token")
	var conversation contracts.HTTPConversation
	if err := json.Unmarshal(loadExample(t), &conversation); err != nil {
		t.Fatalf("decode example: %v", err)
	}
	conversation.SchemaVersion = "wrong.version"
	body, err := json.Marshal(conversation)
	if err != nil {
		t.Fatalf("encode invalid example: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleConversationRejectsOversizedBody(t *testing.T) {
	service := NewService(&fakeStore{}, nil, "agent-token")
	service.MaxBodyBytes = 8

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleConversationRejectsNonJSONContentType(t *testing.T) {
	service := NewService(&fakeStore{}, nil, "agent-token")
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleConversationDoesNotAnalyzeDroppedLogs(t *testing.T) {
	store := &fakeStore{err: core.ErrTrafficLogDropped}
	analyzer := &fakeAnalyzer{}
	service := NewService(store, analyzer, "agent-token")

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if analyzer.count != 0 {
		t.Fatalf("expected analyzer not to run for dropped logs, got %d", analyzer.count)
	}
	var response Response
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "dropped" {
		t.Fatalf("unexpected response status: %s", response.Status)
	}
}

type fakeStore struct {
	logs []core.TrafficLog
	err  error
}

func (f *fakeStore) SaveLog(logEntry core.TrafficLog) error {
	if f.err != nil {
		return f.err
	}
	f.logs = append(f.logs, logEntry)
	return nil
}

type fakeAnalyzer struct {
	count int
}

func (f *fakeAnalyzer) ProcessLog(core.TrafficLog) {
	f.count++
}

func loadExample(t *testing.T) []byte {
	t.Helper()

	path := filepath.Join("..", "..", "contracts", "examples", "http.conversation.v1.example.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	return raw
}
