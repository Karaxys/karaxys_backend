package deadletter

import (
	"context"
	"strings"
	"testing"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/queue"
)

func TestConsumerPersistsDeadLetterAndCommits(t *testing.T) {
	message := testDeadLetterMessage(t)
	queueConsumer := &fakeQueueConsumer{messages: []queue.Message{message}}
	store := &fakeStore{}
	consumer := NewConsumer(queueConsumer, store)

	if err := consumer.ProcessOne(context.Background()); err != nil {
		t.Fatalf("process one: %v", err)
	}
	if len(store.deadLetters) != 1 {
		t.Fatalf("expected one persisted dead letter, got %d", len(store.deadLetters))
	}
	deadLetter := store.deadLetters[0]
	if deadLetter.Reason != "runtime_analyzer_processing_failed" || deadLetter.SourceTopic != queue.TopicHTTPConversations || deadLetter.EventID != "event-1" {
		t.Fatalf("unexpected dead letter: %+v", deadLetter)
	}
	if len(queueConsumer.committed) != 1 {
		t.Fatalf("expected message commit, got %d", len(queueConsumer.committed))
	}
}

func TestConsumerPersistsDecodeFailureAndCommits(t *testing.T) {
	queueConsumer := &fakeQueueConsumer{messages: []queue.Message{{
		Topic:     queue.TopicIngestDeadLetter,
		Key:       "bad-dlq",
		Value:     []byte("not-json-password=topsecretvalue"),
		Timestamp: time.Now().UTC(),
	}}}
	store := &fakeStore{}
	consumer := NewConsumer(queueConsumer, store)

	if err := consumer.ProcessOne(context.Background()); err != nil {
		t.Fatalf("process one: %v", err)
	}
	if len(store.deadLetters) != 1 || store.deadLetters[0].Reason != "dead_letter_decode_failed" {
		t.Fatalf("expected decode failure dead letter, got %+v", store.deadLetters)
	}
	if strings.Contains(store.deadLetters[0].PayloadExcerpt, "topsecretvalue") {
		t.Fatalf("expected decode failure payload to be redacted, got %q", store.deadLetters[0].PayloadExcerpt)
	}
	if len(queueConsumer.committed) != 1 {
		t.Fatalf("expected message commit, got %d", len(queueConsumer.committed))
	}
}

func testDeadLetterMessage(t *testing.T) queue.Message {
	t.Helper()
	payload := queue.DeadLetter{
		SchemaVersion: queue.EventDeadLetterV1,
		SourceTopic:   queue.TopicHTTPConversations,
		EventID:       "event-1",
		Reason:        "runtime_analyzer_processing_failed",
		Error:         "decode failed",
		Payload:       `{"conversation_id":"6650f8cb1c5e7c6c1f93a111"}`,
		CreatedAt:     time.Now().UTC(),
	}
	envelope, err := queue.NewEnvelope(
		queue.EventDeadLetterV1,
		queue.EventDeadLetterV1,
		payload,
		queue.WithEventID("dead_letter:event-1"),
		queue.WithIdempotencyKey("dead_letter:event-1"),
	)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	message, err := queue.EncodeEnvelope(queue.TopicIngestDeadLetter, envelope.IdempotencyKey, envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return message
}

type fakeQueueConsumer struct {
	messages  []queue.Message
	committed []queue.Message
}

func (f *fakeQueueConsumer) Consume(context.Context) (queue.Message, error) {
	if len(f.messages) == 0 {
		return queue.Message{}, queue.ErrNoMessage
	}
	message := f.messages[0]
	f.messages = f.messages[1:]
	return message, nil
}

func (f *fakeQueueConsumer) Commit(_ context.Context, message queue.Message) error {
	f.committed = append(f.committed, message)
	return nil
}

func (f *fakeQueueConsumer) Close() error {
	return nil
}

type fakeStore struct {
	deadLetters []core.IngestDeadLetter
}

func (f *fakeStore) SaveIngestDeadLetter(deadLetter core.IngestDeadLetter) error {
	f.deadLetters = append(f.deadLetters, deadLetter)
	return nil
}
