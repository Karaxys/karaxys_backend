package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	TopicHTTPConversations = "karaxys.http.conversations"
	TopicAnalyzerJobs      = "karaxys.analyzer.jobs"
	TopicIngestDeadLetter  = "karaxys.ingest.dead_letter"

	HeaderSchemaVersion  = "schema_version"
	HeaderTenantID       = "tenant_id"
	HeaderProjectID      = "project_id"
	HeaderAgentID        = "agent_id"
	HeaderCaptureSource  = "capture_source"
	HeaderIdempotencyKey = "idempotency_key"
)

const (
	EventHTTPConversationV1 = "queue.http_conversation.v1"
	EventAnalyzerJobV1      = "queue.analyzer_job.v1"
	EventDeadLetterV1       = "queue.dead_letter.v1"
)

const (
	PayloadHTTPConversationPersistedV1 = "http.conversation.persisted.v1"
)

var DefaultTopics = []string{
	TopicHTTPConversations,
	TopicAnalyzerJobs,
	TopicIngestDeadLetter,
}

var ErrNoMessage = errors.New("queue has no available message")

type Message struct {
	Topic     string
	Key       string
	Value     []byte
	Headers   map[string]string
	Timestamp time.Time
	Attempts  int
	AckToken  any
}

type Producer interface {
	Produce(ctx context.Context, message Message) error
	Close() error
}

type Consumer interface {
	Consume(ctx context.Context) (Message, error)
	Commit(ctx context.Context, message Message) error
	Close() error
}

type Envelope struct {
	SchemaVersion  string            `json:"schema_version"`
	EventID        string            `json:"event_id"`
	IdempotencyKey string            `json:"idempotency_key"`
	TenantID       string            `json:"tenant_id,omitempty"`
	ProjectID      string            `json:"project_id,omitempty"`
	AgentID        string            `json:"agent_id,omitempty"`
	CaptureSource  string            `json:"capture_source,omitempty"`
	PayloadType    string            `json:"payload_type"`
	Payload        json.RawMessage   `json:"payload"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

type AnalyzerJob struct {
	SchemaVersion  string    `json:"schema_version"`
	ConversationID string    `json:"conversation_id"`
	TrafficLogID   string    `json:"traffic_log_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type HTTPConversationEvent struct {
	SchemaVersion    string    `json:"schema_version"`
	ConversationID   string    `json:"conversation_id"`
	ConversationHash string    `json:"conversation_hash,omitempty"`
	TenantID         string    `json:"tenant_id,omitempty"`
	ProjectID        string    `json:"project_id,omitempty"`
	AgentID          string    `json:"agent_id,omitempty"`
	CaptureSource    string    `json:"capture_source,omitempty"`
	CaptureMode      string    `json:"capture_mode,omitempty"`
	CapturedAt       time.Time `json:"captured_at"`
	Method           string    `json:"method"`
	Host             string    `json:"host"`
	Path             string    `json:"path"`
	ResponseStatus   int       `json:"response_status,omitempty"`
}

type DeadLetter struct {
	SchemaVersion string    `json:"schema_version"`
	SourceTopic   string    `json:"source_topic,omitempty"`
	EventID       string    `json:"event_id,omitempty"`
	Reason        string    `json:"reason"`
	Error         string    `json:"error,omitempty"`
	Payload       string    `json:"payload,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewEnvelope(schemaVersion string, payloadType string, payload any, options ...EnvelopeOption) (Envelope, error) {
	if strings.TrimSpace(schemaVersion) == "" {
		return Envelope{}, fmt.Errorf("schema version is required")
	}
	if strings.TrimSpace(payloadType) == "" {
		return Envelope{}, fmt.Errorf("payload type is required")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{
		SchemaVersion: schemaVersion,
		PayloadType:   payloadType,
		Payload:       raw,
		CreatedAt:     time.Now().UTC(),
	}
	for _, option := range options {
		option(&envelope)
	}
	if strings.TrimSpace(envelope.EventID) == "" {
		envelope.EventID = envelope.IdempotencyKey
	}
	return envelope, nil
}

type EnvelopeOption func(*Envelope)

func WithIdentity(tenantID string, projectID string, agentID string, captureSource string) EnvelopeOption {
	return func(envelope *Envelope) {
		envelope.TenantID = strings.TrimSpace(tenantID)
		envelope.ProjectID = strings.TrimSpace(projectID)
		envelope.AgentID = strings.TrimSpace(agentID)
		envelope.CaptureSource = strings.TrimSpace(captureSource)
	}
}

func WithIdempotencyKey(key string) EnvelopeOption {
	return func(envelope *Envelope) {
		envelope.IdempotencyKey = strings.TrimSpace(key)
	}
}

func WithEventID(eventID string) EnvelopeOption {
	return func(envelope *Envelope) {
		envelope.EventID = strings.TrimSpace(eventID)
	}
}

func WithMetadata(metadata map[string]string) EnvelopeOption {
	return func(envelope *Envelope) {
		if len(metadata) == 0 {
			return
		}
		envelope.Metadata = make(map[string]string, len(metadata))
		for key, value := range metadata {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			envelope.Metadata[key] = strings.TrimSpace(value)
		}
	}
}

func EncodeEnvelope(topic string, key string, envelope Envelope) (Message, error) {
	if strings.TrimSpace(topic) == "" {
		return Message{}, fmt.Errorf("topic is required")
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return Message{}, err
	}
	return Message{
		Topic: strings.TrimSpace(topic),
		Key:   strings.TrimSpace(key),
		Value: raw,
		Headers: map[string]string{
			HeaderSchemaVersion:  envelope.SchemaVersion,
			HeaderTenantID:       envelope.TenantID,
			HeaderProjectID:      envelope.ProjectID,
			HeaderAgentID:        envelope.AgentID,
			HeaderCaptureSource:  envelope.CaptureSource,
			HeaderIdempotencyKey: envelope.IdempotencyKey,
		},
		Timestamp: envelope.CreatedAt,
	}, nil
}

func DecodeEnvelope(message Message) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(message.Value, &envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func NormalizeTopic(topic string) string {
	return strings.TrimSpace(topic)
}

func HTTPConversationIdempotencyKey(conversationID string) string {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	return "http_conversation:" + conversationID
}
