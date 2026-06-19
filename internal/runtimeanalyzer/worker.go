package runtimeanalyzer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/queue"
	"karaxys_backend/internal/security/redact"
)

const deadLetterPayloadMaxBytes = 8 * 1024

type TrafficLogStore interface {
	GetTrafficLogByConversationID(ctx context.Context, conversationID string) (core.TrafficLog, error)
}

type Analyzer interface {
	ProcessLog(core.TrafficLog)
}

type Logger interface {
	Printf(format string, args ...any)
}

type Worker struct {
	Consumer           queue.Consumer
	DeadLetterProducer queue.Producer
	Store              TrafficLogStore
	Analyzer           Analyzer
	Metrics            *Metrics
	Logger             Logger
	IdleSleep          time.Duration
	Now                func() time.Time
}

func NewWorker(consumer queue.Consumer, deadLetterProducer queue.Producer, store TrafficLogStore, analyzer Analyzer) *Worker {
	return &Worker{
		Consumer:           consumer,
		DeadLetterProducer: deadLetterProducer,
		Store:              store,
		Analyzer:           analyzer,
		Metrics:            &Metrics{},
		Logger:             log.Default(),
		IdleSleep:          250 * time.Millisecond,
		Now:                func() time.Time { return time.Now().UTC() },
	}
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := w.ProcessOne(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, queue.ErrNoMessage) {
				w.sleepIdle(ctx)
				continue
			}
			w.logf("runtime analyzer processing error: %v", err)
		}
	}
}

func (w *Worker) ProcessOne(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	message, err := w.Consumer.Consume(ctx)
	if err != nil {
		return err
	}
	now := w.now()
	w.Metrics.observeConsumed(message.Timestamp, now)

	if err := w.processMessage(ctx, message); err != nil {
		w.Metrics.observeFailed()
		if dlqErr := w.publishDeadLetter(ctx, message, err); dlqErr != nil {
			return fmt.Errorf("process message: %w; publish dead letter: %v", err, dlqErr)
		}
		w.Metrics.observeDeadLettered()
		if commitErr := w.Consumer.Commit(ctx, message); commitErr != nil {
			return fmt.Errorf("process message: %w; commit failed message: %v", err, commitErr)
		}
		w.Metrics.observeCommitted()
		return err
	}
	if err := w.Consumer.Commit(ctx, message); err != nil {
		w.Metrics.observeFailed()
		return err
	}
	w.Metrics.observeProcessed()
	w.Metrics.observeCommitted()
	return nil
}

func (w *Worker) Close() error {
	var errs []error
	if w.Consumer != nil {
		if err := w.Consumer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if w.DeadLetterProducer != nil {
		if err := w.DeadLetterProducer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (w *Worker) processMessage(ctx context.Context, message queue.Message) error {
	envelope, err := queue.DecodeEnvelope(message)
	if err != nil {
		return fmt.Errorf("decode queue envelope: %w", err)
	}
	if envelope.SchemaVersion != queue.EventHTTPConversationV1 {
		return fmt.Errorf("unexpected envelope schema %q", envelope.SchemaVersion)
	}
	if envelope.PayloadType != queue.PayloadHTTPConversationPersistedV1 {
		return fmt.Errorf("unexpected payload type %q", envelope.PayloadType)
	}

	var event queue.HTTPConversationEvent
	if err := json.Unmarshal(envelope.Payload, &event); err != nil {
		return fmt.Errorf("decode conversation event payload: %w", err)
	}
	if strings.TrimSpace(event.ConversationID) == "" {
		return fmt.Errorf("conversation event missing conversation_id")
	}

	logEntry, err := w.Store.GetTrafficLogByConversationID(ctx, event.ConversationID)
	if err != nil {
		return fmt.Errorf("load traffic log conversation_id=%s: %w", event.ConversationID, err)
	}
	w.Analyzer.ProcessLog(logEntry)
	return nil
}

func (w *Worker) publishDeadLetter(ctx context.Context, message queue.Message, cause error) error {
	if w.DeadLetterProducer == nil {
		return nil
	}
	eventID := deadLetterEventID(message)
	deadLetter := queue.DeadLetter{
		SchemaVersion: queue.EventDeadLetterV1,
		SourceTopic:   message.Topic,
		EventID:       eventID,
		Reason:        "runtime_analyzer_processing_failed",
		Error:         cause.Error(),
		Payload:       redact.Text(truncatePayload(message.Value, deadLetterPayloadMaxBytes)),
		CreatedAt:     w.now(),
	}
	envelope, err := queue.NewEnvelope(
		queue.EventDeadLetterV1,
		queue.EventDeadLetterV1,
		deadLetter,
		queue.WithEventID("dead_letter:"+eventID),
		queue.WithIdempotencyKey("dead_letter:"+eventID),
	)
	if err != nil {
		return err
	}
	dlqMessage, err := queue.EncodeEnvelope(queue.TopicIngestDeadLetter, envelope.IdempotencyKey, envelope)
	if err != nil {
		return err
	}
	return w.DeadLetterProducer.Produce(ctx, dlqMessage)
}

func (w *Worker) validate() error {
	if w == nil {
		return fmt.Errorf("runtime analyzer worker is nil")
	}
	if w.Consumer == nil {
		return fmt.Errorf("runtime analyzer consumer is required")
	}
	if w.Store == nil {
		return fmt.Errorf("runtime analyzer traffic log store is required")
	}
	if w.Analyzer == nil {
		return fmt.Errorf("runtime analyzer processor is required")
	}
	if w.Metrics == nil {
		w.Metrics = &Metrics{}
	}
	if w.Now == nil {
		w.Now = func() time.Time { return time.Now().UTC() }
	}
	return nil
}

func (w *Worker) now() time.Time {
	if w != nil && w.Now != nil {
		return w.Now()
	}
	return time.Now().UTC()
}

func (w *Worker) sleepIdle(ctx context.Context) {
	sleep := w.IdleSleep
	if sleep <= 0 {
		return
	}
	timer := time.NewTimer(sleep)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (w *Worker) logf(format string, args ...any) {
	if w != nil && w.Logger != nil {
		w.Logger.Printf(format, args...)
	}
}

func deadLetterEventID(message queue.Message) string {
	if envelope, err := queue.DecodeEnvelope(message); err == nil {
		if strings.TrimSpace(envelope.EventID) != "" {
			return envelope.EventID
		}
		if strings.TrimSpace(envelope.IdempotencyKey) != "" {
			return envelope.IdempotencyKey
		}
	}
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
