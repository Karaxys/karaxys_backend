package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"karaxys_backend/internal/contracts"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/queue"
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
	if saved.ConversationID != "6650f8cb1c5e7c6c1f93a111" {
		t.Fatalf("unexpected analyzer conversation id: %s", saved.ConversationID)
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

func TestHandleConversationAcceptsDynamicAgentTokenAndBindsIdentity(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store, nil, "", func(token string) (*AgentAuth, bool) {
		if token != "dynamic-agent-token" {
			return nil, false
		}
		return &AgentAuth{
			AgentID:  "registered-agent",
			TenantID: "account-1",
		}, true
	})

	var conversation contracts.HTTPConversation
	if err := json.Unmarshal(loadExample(t), &conversation); err != nil {
		t.Fatalf("decode example: %v", err)
	}
	conversation.AgentID = ""
	body, err := json.Marshal(conversation)
	if err != nil {
		t.Fatalf("encode conversation: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dynamic-agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.logs) != 1 {
		t.Fatalf("expected saved log")
	}
	if store.logs[0].AgentID != "registered-agent" || store.logs[0].TenantID != "account-1" {
		t.Fatalf("identity was not bound from token: %+v", store.logs[0])
	}
}

func TestHandleConversationPublishesConversationEventInsteadOfInlineAnalyzer(t *testing.T) {
	store := &fakeStore{}
	analyzer := &fakeAnalyzer{}
	publisher := &fakePublisher{}
	service := NewService(store, analyzer, "agent-token")
	service.Publisher = publisher

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if analyzer.count != 0 {
		t.Fatalf("expected inline analyzer not to run when queue publisher is configured, got %d", analyzer.count)
	}
	if len(publisher.events) != 1 {
		t.Fatalf("expected one published event, got %d", len(publisher.events))
	}
	event := publisher.events[0]
	if event.ConversationID != "6650f8cb1c5e7c6c1f93a111" || event.CaptureSource != "ebpf" || event.Method != http.MethodGet {
		t.Fatalf("unexpected published event: %+v", event)
	}
	if event.ConversationHash == "" {
		t.Fatalf("expected published event to include conversation hash")
	}
	if event.Host != "api.example.local" || event.Path != "/api/v1/users" || event.ResponseStatus != 200 {
		t.Fatalf("unexpected published request metadata: %+v", event)
	}
	if len(store.ingestionLogs) != 1 || store.ingestionLogs[0].Status != "accepted" {
		t.Fatalf("expected accepted ingestion log, got %+v", store.ingestionLogs)
	}
}

func TestHandleConversationReturnsDuplicateWithoutAnalysisOrPublish(t *testing.T) {
	store := &fakeStore{err: core.ErrTrafficLogDuplicate}
	analyzer := &fakeAnalyzer{}
	publisher := &fakePublisher{}
	service := NewService(store, analyzer, "agent-token")
	service.Publisher = publisher

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	var response Response
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "duplicate" {
		t.Fatalf("expected duplicate response, got %+v", response)
	}
	if analyzer.count != 0 || len(publisher.events) != 0 || len(store.conversations) != 0 {
		t.Fatalf("duplicate should not analyze, publish, or save conversation: analyzer=%d published=%d conversations=%d", analyzer.count, len(publisher.events), len(store.conversations))
	}
	if len(store.ingestionLogs) != 1 || store.ingestionLogs[0].Status != "duplicate" {
		t.Fatalf("expected duplicate ingestion log, got %+v", store.ingestionLogs)
	}
}

func TestHandleConversationFailsClosedWhenConversationEventPublishFails(t *testing.T) {
	store := &fakeStore{}
	analyzer := &fakeAnalyzer{}
	service := NewService(store, analyzer, "agent-token")
	service.Publisher = &fakePublisher{err: errors.New("queue unavailable")}

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(loadExample(t)))
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if analyzer.count != 0 {
		t.Fatalf("expected inline analyzer not to run after queue publish failure, got %d", analyzer.count)
	}
	if len(store.logs) != 1 || len(store.conversations) != 1 {
		t.Fatalf("expected persisted log and conversation before publish failure, got logs=%d conversations=%d", len(store.logs), len(store.conversations))
	}
	if len(store.ingestionLogs) != 1 || store.ingestionLogs[0].Status != "failed" {
		t.Fatalf("expected failed ingestion log, got %+v", store.ingestionLogs)
	}
	if len(store.deadLetters) != 1 || store.deadLetters[0].Reason != "conversation_event_publish_failed" {
		t.Fatalf("expected publish failure dead letter, got %+v", store.deadLetters)
	}
}

func TestConversationHashIgnoresConversationObjectID(t *testing.T) {
	var first contracts.HTTPConversation
	if err := json.Unmarshal(loadExample(t), &first); err != nil {
		t.Fatalf("decode first example: %v", err)
	}
	second := first
	second.ID.OID = "6650f8cb1c5e7c6c1f93a222"

	firstHash := ConversationHash(first)
	secondHash := ConversationHash(second)
	if firstHash == "" || secondHash == "" {
		t.Fatalf("expected non-empty hashes: first=%q second=%q", firstHash, secondHash)
	}
	if firstHash != secondHash {
		t.Fatalf("expected hash to ignore conversation object id: first=%s second=%s", firstHash, secondHash)
	}
	second.HTTP.Request.Path = "/api/v1/users/2"
	if ConversationHash(second) == firstHash {
		t.Fatalf("expected hash to change when request content changes")
	}
}

func TestHandleConversationRejectsAgentIdentityMismatch(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store, nil, "", func(token string) (*AgentAuth, bool) {
		if token != "dynamic-agent-token" {
			return nil, false
		}
		return &AgentAuth{AgentID: "registered-agent"}, true
	})

	var conversation contracts.HTTPConversation
	if err := json.Unmarshal(loadExample(t), &conversation); err != nil {
		t.Fatalf("decode example: %v", err)
	}
	conversation.AgentID = "spoofed-agent"
	body, err := json.Marshal(conversation)
	if err != nil {
		t.Fatalf("encode conversation: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dynamic-agent-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	service.HandleConversation(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.logs) != 0 {
		t.Fatalf("expected no persisted logs on identity mismatch")
	}
	if len(store.deadLetters) != 1 || store.deadLetters[0].Reason != "agent_identity_mismatch" {
		t.Fatalf("expected identity mismatch dead letter, got %+v", store.deadLetters)
	}
}

func TestQueuePublisherProducesConversationEnvelope(t *testing.T) {
	broker := queue.NewMemoryBroker(1)
	publisher := NewQueuePublisher(broker.Producer())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	event := queue.HTTPConversationEvent{
		SchemaVersion:    queue.EventHTTPConversationV1,
		ConversationID:   "6650f8cb1c5e7c6c1f93a111",
		ConversationHash: "hash-1",
		TenantID:         "tenant-1",
		ProjectID:        "project-1",
		AgentID:          "agent-1",
		CaptureSource:    "ebpf",
		CaptureMode:      "container",
		CapturedAt:       time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		Method:           http.MethodPost,
		Host:             "api.example.local",
		Path:             "/users/login",
		ResponseStatus:   200,
	}

	if err := publisher.PublishConversation(ctx, event); err != nil {
		t.Fatalf("publish conversation: %v", err)
	}
	message, err := broker.Consumer(queue.TopicHTTPConversations).Consume(ctx)
	if err != nil {
		t.Fatalf("consume published message: %v", err)
	}
	if message.Key != queue.HTTPConversationIdempotencyKey(event.ConversationID) {
		t.Fatalf("unexpected message key: %s", message.Key)
	}
	if message.Headers[queue.HeaderTenantID] != "tenant-1" || message.Headers[queue.HeaderAgentID] != "agent-1" {
		t.Fatalf("unexpected message headers: %+v", message.Headers)
	}

	envelope, err := queue.DecodeEnvelope(message)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.PayloadType != queue.PayloadHTTPConversationPersistedV1 || envelope.IdempotencyKey != message.Key {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	var payload queue.HTTPConversationEvent
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.ConversationID != event.ConversationID || payload.Path != event.Path {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if payload.ConversationHash != event.ConversationHash {
		t.Fatalf("unexpected payload hash: %+v", payload)
	}
	if strings.Contains(string(message.Value), "Authorization") || strings.Contains(string(message.Value), "password") {
		t.Fatalf("queue message contains sensitive raw HTTP material: %s", string(message.Value))
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

type fakePublisher struct {
	events []queue.HTTPConversationEvent
	err    error
}

func (f *fakePublisher) PublishConversation(_ context.Context, event queue.HTTPConversationEvent) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
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
