package ingest

import (
	"context"
	"fmt"
	"strings"

	"karaxys_backend/internal/queue"
)

type EventPublisher interface {
	PublishConversation(ctx context.Context, event queue.HTTPConversationEvent) error
}

type QueuePublisher struct {
	Producer queue.Producer
	Topic    string
}

func NewQueuePublisher(producer queue.Producer) *QueuePublisher {
	return &QueuePublisher{
		Producer: producer,
		Topic:    queue.TopicHTTPConversations,
	}
}

func (p *QueuePublisher) PublishConversation(ctx context.Context, event queue.HTTPConversationEvent) error {
	if p == nil || p.Producer == nil {
		return fmt.Errorf("conversation event producer is not configured")
	}
	if strings.TrimSpace(event.ConversationID) == "" {
		return fmt.Errorf("conversation id is required")
	}
	if event.SchemaVersion == "" {
		event.SchemaVersion = queue.EventHTTPConversationV1
	}
	topic := strings.TrimSpace(p.Topic)
	if topic == "" {
		topic = queue.TopicHTTPConversations
	}
	idempotencyKey := queue.HTTPConversationIdempotencyKey(event.ConversationID)
	envelope, err := queue.NewEnvelope(
		queue.EventHTTPConversationV1,
		queue.PayloadHTTPConversationPersistedV1,
		event,
		queue.WithEventID(idempotencyKey),
		queue.WithIdempotencyKey(idempotencyKey),
		queue.WithIdentity(event.TenantID, event.ProjectID, event.AgentID, event.CaptureSource),
	)
	if err != nil {
		return err
	}
	message, err := queue.EncodeEnvelope(topic, idempotencyKey, envelope)
	if err != nil {
		return err
	}
	return p.Producer.Produce(ctx, message)
}
