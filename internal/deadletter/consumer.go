package deadletter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/queue"
	"karaxys_backend/internal/security/redact"
)

const payloadExcerptMaxBytes = 8 * 1024

type Store interface {
	SaveIngestDeadLetter(core.IngestDeadLetter) error
}

type Consumer struct {
	Queue queue.Consumer
	Store Store
	Now   func() time.Time
}

func NewConsumer(queueConsumer queue.Consumer, store Store) *Consumer {
	return &Consumer{
		Queue: queueConsumer,
		Store: store,
		Now:   func() time.Time { return time.Now().UTC() },
	}
}

func (c *Consumer) Run(ctx context.Context) error {
	if err := c.validate(); err != nil {
		return err
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := c.ProcessOne(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, queue.ErrNoMessage) {
				continue
			}
			return err
		}
	}
}

func (c *Consumer) ProcessOne(ctx context.Context) error {
	if err := c.validate(); err != nil {
		return err
	}
	message, err := c.Queue.Consume(ctx)
	if err != nil {
		return err
	}
	deadLetter, err := c.decode(message)
	if err != nil {
		deadLetter = core.IngestDeadLetter{
			CreatedAt:      c.now(),
			Reason:         "dead_letter_decode_failed",
			SourceTopic:    message.Topic,
			EventID:        fallbackEventID(message),
			Error:          err.Error(),
			PayloadExcerpt: truncatePayload(message.Value, payloadExcerptMaxBytes),
		}
	}
	if err := c.Store.SaveIngestDeadLetter(redact.IngestDeadLetter(deadLetter)); err != nil {
		return err
	}
	return c.Queue.Commit(ctx, message)
}

func (c *Consumer) Close() error {
	if c == nil || c.Queue == nil {
		return nil
	}
	return c.Queue.Close()
}

func (c *Consumer) decode(message queue.Message) (core.IngestDeadLetter, error) {
	envelope, err := queue.DecodeEnvelope(message)
	if err != nil {
		return core.IngestDeadLetter{}, fmt.Errorf("decode dead-letter envelope: %w", err)
	}
	if envelope.SchemaVersion != queue.EventDeadLetterV1 {
		return core.IngestDeadLetter{}, fmt.Errorf("unexpected dead-letter schema %q", envelope.SchemaVersion)
	}
	var payload queue.DeadLetter
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return core.IngestDeadLetter{}, fmt.Errorf("decode dead-letter payload: %w", err)
	}
	createdAt := payload.CreatedAt
	if createdAt.IsZero() {
		createdAt = c.now()
	}
	return core.IngestDeadLetter{
		CreatedAt:      createdAt,
		Reason:         payload.Reason,
		SchemaVersion:  payload.SchemaVersion,
		SourceTopic:    payload.SourceTopic,
		EventID:        payload.EventID,
		Error:          payload.Error,
		PayloadExcerpt: payload.Payload,
	}, nil
}

func (c *Consumer) validate() error {
	if c == nil {
		return fmt.Errorf("dead-letter consumer is nil")
	}
	if c.Queue == nil {
		return fmt.Errorf("dead-letter queue consumer is required")
	}
	if c.Store == nil {
		return fmt.Errorf("dead-letter store is required")
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	return nil
}

func (c *Consumer) now() time.Time {
	if c != nil && c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

func fallbackEventID(message queue.Message) string {
	if strings.TrimSpace(message.Key) != "" {
		return message.Key
	}
	return fmt.Sprintf("%s:%d", queue.NormalizeTopic(message.Topic), message.Timestamp.UnixNano())
}

func truncatePayload(raw []byte, maxBytes int) string {
	if maxBytes <= 0 || len(raw) <= maxBytes {
		return strings.ToValidUTF8(string(raw), ".")
	}
	return strings.ToValidUTF8(string(raw[:maxBytes]), ".")
}
