package ingest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"karaxys_backend/internal/contracts"
	"karaxys_backend/internal/core"
)

const DefaultMaxBodyBytes = 5 * 1024 * 1024
const payloadExcerptMaxBytes = 8 * 1024

type LogStore interface {
	SaveLog(core.TrafficLog) error
}

type ConversationStore interface {
	SaveConversation(core.TrafficConversation) error
}

type IngestionRecorder interface {
	SaveIngestionLog(core.IngestionLog) error
}

type DeadLetterStore interface {
	SaveIngestDeadLetter(core.IngestDeadLetter) error
}

type Analyzer interface {
	ProcessLog(core.TrafficLog)
}

type Service struct {
	Store        LogStore
	Analyzer     Analyzer
	AgentToken   string
	MaxBodyBytes int64
}

type Response struct {
	Status        string `json:"status"`
	SchemaVersion string `json:"schema_version"`
}

func NewService(store LogStore, analyzer Analyzer, agentToken string) *Service {
	return &Service{
		Store:        store,
		Analyzer:     analyzer,
		AgentToken:   agentToken,
		MaxBodyBytes: DefaultMaxBodyBytes,
	}
}

func (s *Service) HandleConversation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.AgentToken == "" {
		http.Error(w, "Ingestion disabled", http.StatusServiceUnavailable)
		return
	}
	if !s.authorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if s.Store == nil {
		http.Error(w, "Ingestion store unavailable", http.StatusInternalServerError)
		return
	}

	limit := s.MaxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	conversation, err := contracts.DecodeAndValidateHTTPConversation(raw)
	if err != nil {
		s.recordDeadLetter("invalid_conversation_contract", raw, r)
		http.Error(w, "Invalid conversation contract", http.StatusBadRequest)
		return
	}

	logEntry := ConversationToTrafficLog(conversation)
	if err := s.Store.SaveLog(logEntry); err != nil {
		if errors.Is(err, core.ErrTrafficLogDropped) {
			s.recordIngestionLog("dropped", conversation, "traffic log dropped by retention or noise policy")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(Response{
				Status:        "dropped",
				SchemaVersion: conversation.SchemaVersion,
			})
			return
		}
		s.recordIngestionLog("failed", conversation, err.Error())
		s.recordDeadLetter("traffic_log_persist_failed", raw, r)
		http.Error(w, "Failed to persist conversation", http.StatusInternalServerError)
		return
	}
	if conversationStore, ok := s.Store.(ConversationStore); ok {
		if err := conversationStore.SaveConversation(ConversationToTrafficConversation(conversation)); err != nil {
			s.recordIngestionLog("failed", conversation, err.Error())
			s.recordDeadLetter("traffic_conversation_persist_failed", raw, r)
			http.Error(w, "Failed to persist conversation", http.StatusInternalServerError)
			return
		}
	}
	if s.Analyzer != nil {
		s.Analyzer.ProcessLog(logEntry)
	}
	s.recordIngestionLog("accepted", conversation, "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(Response{
		Status:        "accepted",
		SchemaVersion: conversation.SchemaVersion,
	})
}

func ConversationToTrafficLog(conversation contracts.HTTPConversation) core.TrafficLog {
	return core.TrafficLog{
		SchemaVersion: conversation.SchemaVersion,
		CaptureSource: conversation.CaptureSource,
		CaptureMode:   conversation.CaptureMode,
		AgentID:       conversation.AgentID,
		CreatedAt:     conversation.CapturedAt.Date,
		Method:        conversation.HTTP.Request.Method,
		URL:           conversation.HTTP.Request.URL,
		Host:          conversation.HTTP.Request.Host,
		Path:          analyzerPath(conversation.HTTP.Request),
		ReqHeaders:    conversation.HTTP.Request.Headers,
		ReqBody:       conversation.HTTP.Request.Body,
		RespStatus:    conversation.HTTP.Response.Status,
		RespBody:      conversation.HTTP.Response.Body,
		Tags:          []string{"capture_source:" + conversation.CaptureSource},
	}
}

func ConversationToTrafficConversation(conversation contracts.HTTPConversation) core.TrafficConversation {
	respStatusCode := 0
	if conversation.HTTP.Response.StatusCode != nil {
		respStatusCode = *conversation.HTTP.Response.StatusCode
	}
	return core.TrafficConversation{
		ConversationID: conversation.ID.OID,
		SchemaVersion:  conversation.SchemaVersion,
		TenantID:       conversation.TenantID,
		ProjectID:      conversation.ProjectID,
		AgentID:        conversation.AgentID,
		CaptureSource:  conversation.CaptureSource,
		CaptureMode:    conversation.CaptureMode,
		CapturedAt:     conversation.CapturedAt.Date,
		Method:         conversation.HTTP.Request.Method,
		URL:            conversation.HTTP.Request.URL,
		Host:           conversation.HTTP.Request.Host,
		Path:           analyzerPath(conversation.HTTP.Request),
		ReqHeaders:     conversation.HTTP.Request.Headers,
		ReqBody:        conversation.HTTP.Request.Body,
		RespStatus:     conversation.HTTP.Response.Status,
		RespStatusCode: respStatusCode,
		RespHeaders:    conversation.HTTP.Response.Headers,
		RespBody:       conversation.HTTP.Response.Body,
	}
}

func (s *Service) authorized(r *http.Request) bool {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = r.Header.Get("X-API-Key")
	}
	if token == "" {
		return false
	}
	tokenHash := sha256.Sum256([]byte(token))
	expectedHash := sha256.Sum256([]byte(s.AgentToken))
	return subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func isJSONContentType(value string) bool {
	if value == "" {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return mediaType == "application/json"
}

func analyzerPath(request contracts.HTTPRequest) string {
	if parsed, err := url.ParseRequestURI(request.Path); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if parsed, err := url.Parse(request.URL); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	return request.Path
}

func (s *Service) recordIngestionLog(status string, conversation contracts.HTTPConversation, message string) {
	recorder, ok := s.Store.(IngestionRecorder)
	if !ok {
		return
	}
	_ = recorder.SaveIngestionLog(core.IngestionLog{
		Status:         status,
		SchemaVersion:  conversation.SchemaVersion,
		CaptureSource:  conversation.CaptureSource,
		AgentID:        conversation.AgentID,
		ConversationID: conversation.ID.OID,
		Method:         conversation.HTTP.Request.Method,
		Host:           conversation.HTTP.Request.Host,
		Path:           analyzerPath(conversation.HTTP.Request),
		Message:        message,
	})
}

func (s *Service) recordDeadLetter(reason string, raw []byte, r *http.Request) {
	store, ok := s.Store.(DeadLetterStore)
	if !ok {
		return
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
		AgentID       string `json:"agent_id"`
	}
	_ = json.Unmarshal(raw, &envelope)
	_ = store.SaveIngestDeadLetter(core.IngestDeadLetter{
		Reason:         reason,
		SchemaVersion:  envelope.SchemaVersion,
		AgentID:        envelope.AgentID,
		RemoteAddr:     r.RemoteAddr,
		PayloadExcerpt: payloadExcerpt(raw),
	})
}

func payloadExcerpt(raw []byte) string {
	if len(raw) <= payloadExcerptMaxBytes {
		return strings.ToValidUTF8(string(raw), ".")
	}
	return strings.ToValidUTF8(string(raw[:payloadExcerptMaxBytes]), ".")
}
