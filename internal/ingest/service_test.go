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
	if len(store.conversations) != 1 {
		t.Fatalf("expected one saved conversation, got %d", len(store.conversations))
	}
	if len(store.ingestionLogs) != 1 {
		t.Fatalf("expected one ingestion log, got %d", len(store.ingestionLogs))
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
	savedConversation := store.conversations[0]
	if savedConversation.ConversationID != "6650f8cb1c5e7c6c1f93a111" {
		t.Fatalf("unexpected conversation id: %s", savedConversation.ConversationID)
	}
	if savedConversation.RespStatus != "200 OK" || savedConversation.RespStatusCode != 200 {
		t.Fatalf("unexpected response mapping: %+v", savedConversation)
	}
	if store.ingestionLogs[0].Status != "accepted" {
		t.Fatalf("unexpected ingestion log: %+v", store.ingestionLogs[0])
	}

	var response Response
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "accepted" || response.SchemaVersion != contracts.SchemaHTTPConversationV1 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestHandleConversationRedactsSecretsBeforePersistence(t *testing.T) {
	store := &fakeStore{}
	analyzer := &fakeAnalyzer{}
	service := NewService(store, analyzer, "agent-token")
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.signaturevalue"

	var conversation contracts.HTTPConversation
	if err := json.Unmarshal(loadExample(t), &conversation); err != nil {
		t.Fatalf("decode example: %v", err)
	}
	conversation.HTTP.Request.URL = "http://api.example.local/api/v1/users?access_token=query-secret"
	conversation.HTTP.Request.Headers["Authorization"] = []string{"Bearer " + jwt}
	conversation.HTTP.Request.Headers["X-API-Key"] = []string{"api-key-secret"}
	conversation.HTTP.Request.Body = `{"password":"super-secret-value","auth_token":"` + jwt + `"}`
	conversation.HTTP.Response.Headers["Set-Cookie"] = []string{"session=secret-cookie"}
	conversation.HTTP.Response.Body = `{"auth_token":"` + jwt + `"}`
	body, err := json.Marshal(conversation)
	if err != nil {
		t.Fatalf("encode conversation: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.logs) != 1 || len(store.conversations) != 1 {
		t.Fatalf("expected persisted log and conversation, got logs=%d conversations=%d", len(store.logs), len(store.conversations))
	}

	savedLog := store.logs[0]
	assertNotContains(t, savedLog.URL, "query-secret")
	assertNotContains(t, savedLog.ReqBody, "super-secret-value")
	assertNotContains(t, savedLog.ReqBody, jwt)
	assertNotContains(t, savedLog.RespBody, jwt)
	if savedLog.ReqHeaders["Authorization"][0] != "[REDACTED]" {
		t.Fatalf("authorization header not redacted: %+v", savedLog.ReqHeaders)
	}
	if savedLog.ReqHeaders["X-API-Key"][0] != "[REDACTED]" {
		t.Fatalf("api key header not redacted: %+v", savedLog.ReqHeaders)
	}

	savedConversation := store.conversations[0]
	assertNotContains(t, savedConversation.RespHeaders["Set-Cookie"][0], "secret-cookie")
	assertNotContains(t, savedConversation.RespBody, jwt)

	if analyzer.count != 1 {
		t.Fatalf("expected analyzer to run once, got %d", analyzer.count)
	}
	if !strings.Contains(analyzer.lastLog.RespBody, jwt) {
		t.Fatalf("expected analyzer to receive original in-memory body for classification")
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
	if len(service.Store.(*fakeStore).deadLetters) != 1 {
		t.Fatalf("expected one dead letter, got %d", len(service.Store.(*fakeStore).deadLetters))
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
	if len(store.ingestionLogs) != 1 || store.ingestionLogs[0].Status != "dropped" {
		t.Fatalf("expected dropped ingestion log, got %+v", store.ingestionLogs)
	}
	if len(store.conversations) != 0 {
		t.Fatalf("expected no saved conversation for dropped log, got %d", len(store.conversations))
	}
}

type fakeStore struct {
	logs            []core.TrafficLog
	conversations   []core.TrafficConversation
	ingestionLogs   []core.IngestionLog
	deadLetters     []core.IngestDeadLetter
	err             error
	conversationErr error
}

func (f *fakeStore) SaveLog(logEntry core.TrafficLog) error {
	if f.err != nil {
		return f.err
	}
	f.logs = append(f.logs, logEntry)
	return nil
}

func (f *fakeStore) SaveConversation(conversation core.TrafficConversation) error {
	if f.conversationErr != nil {
		return f.conversationErr
	}
	f.conversations = append(f.conversations, conversation)
	return nil
}

func (f *fakeStore) SaveIngestionLog(logEntry core.IngestionLog) error {
	f.ingestionLogs = append(f.ingestionLogs, logEntry)
	return nil
}

func (f *fakeStore) SaveIngestDeadLetter(deadLetter core.IngestDeadLetter) error {
	f.deadLetters = append(f.deadLetters, deadLetter)
	return nil
}

type fakeAnalyzer struct {
	count   int
	lastLog core.TrafficLog
}

func (f *fakeAnalyzer) ProcessLog(logEntry core.TrafficLog) {
	f.count++
	f.lastLog = logEntry
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

func assertNotContains(t *testing.T, value string, secret string) {
	t.Helper()
	if strings.Contains(value, secret) {
		t.Fatalf("expected secret %q to be redacted from %q", secret, value)
	}
}
