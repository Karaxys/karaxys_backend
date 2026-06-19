package runtimeanalyzer

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/queue"
)

func TestWorkerProcessesConversationEventAndCommits(t *testing.T) {
	message := testConversationMessage(t, "6650f8cb1c5e7c6c1f93a111")
	consumer := &fakeConsumer{messages: []queue.Message{message}}
	deadLetters := &fakeProducer{}
	store := &fakeTrafficLogStore{
		logs: map[string]core.TrafficLog{
			"6650f8cb1c5e7c6c1f93a111": {
				ConversationID: "6650f8cb1c5e7c6c1f93a111",
				Method:         "GET",
				URL:            "http://api.example.local/users/1",
				Host:           "api.example.local",
				Path:           "/users/1",
				CreatedAt:      time.Now().UTC(),
			},
		},
	}
	analyzer := &fakeAnalyzer{}
	worker := NewWorker(consumer, deadLetters, store, analyzer)

	if err := worker.ProcessOne(context.Background()); err != nil {
		t.Fatalf("process one: %v", err)
	}
	if analyzer.count != 1 || analyzer.last.ConversationID != "6650f8cb1c5e7c6c1f93a111" {
		t.Fatalf("expected analyzer to process persisted traffic log, got count=%d log=%+v", analyzer.count, analyzer.last)
	}
	if len(consumer.committed) != 1 {
		t.Fatalf("expected one committed message, got %d", len(consumer.committed))
	}
	if len(deadLetters.messages) != 0 {
		t.Fatalf("expected no dead letters, got %d", len(deadLetters.messages))
	}
	snapshot := worker.Metrics.Snapshot()
	if snapshot.Consumed != 1 || snapshot.Processed != 1 || snapshot.Failed != 0 || snapshot.Committed != 1 {
		t.Fatalf("unexpected metrics snapshot: %+v", snapshot)
	}
}

func TestWorkerPublishesDeadLetterAndCommitsInvalidMessage(t *testing.T) {
	consumer := &fakeConsumer{messages: []queue.Message{{
		Topic:     queue.TopicHTTPConversations,
		Key:       "bad-message",
		Value:     []byte(`not-json`),
		Timestamp: time.Now().Add(-2 * time.Second),
	}}}
	deadLetters := &fakeProducer{}
	worker := NewWorker(consumer, deadLetters, &fakeTrafficLogStore{}, &fakeAnalyzer{})

	err := worker.ProcessOne(context.Background())
	if err == nil {
		t.Fatalf("expected invalid message error")
	}
	if len(consumer.committed) != 1 {
		t.Fatalf("expected invalid message to be committed after DLQ publish, got %d", len(consumer.committed))
	}
	if len(deadLetters.messages) != 1 {
		t.Fatalf("expected one dead letter, got %d", len(deadLetters.messages))
	}
	envelope, err := queue.DecodeEnvelope(deadLetters.messages[0])
	if err != nil {
		t.Fatalf("decode dead letter envelope: %v", err)
	}
	var deadLetter queue.DeadLetter
	if err := json.Unmarshal(envelope.Payload, &deadLetter); err != nil {
		t.Fatalf("decode dead letter payload: %v", err)
	}
	if deadLetter.SourceTopic != queue.TopicHTTPConversations || deadLetter.Reason != "runtime_analyzer_processing_failed" {
		t.Fatalf("unexpected dead letter: %+v", deadLetter)
	}
	snapshot := worker.Metrics.Snapshot()
	if snapshot.Consumed != 1 || snapshot.Processed != 0 || snapshot.Failed != 1 || snapshot.DeadLettered != 1 || snapshot.Committed != 1 {
		t.Fatalf("unexpected metrics snapshot: %+v", snapshot)
	}
	if snapshot.LastLag <= 0 {
		t.Fatalf("expected positive lag, got %s", snapshot.LastLag)
	}
}

func TestWorkerPublishesDeadLetterWhenPersistedLogIsMissing(t *testing.T) {
	consumer := &fakeConsumer{messages: []queue.Message{testConversationMessage(t, "6650f8cb1c5e7c6c1f93a111")}}
	deadLetters := &fakeProducer{}
	store := &fakeTrafficLogStore{err: errors.New("not found")}
	analyzer := &fakeAnalyzer{}
	worker := NewWorker(consumer, deadLetters, store, analyzer)

	err := worker.ProcessOne(context.Background())
	if err == nil {
		t.Fatalf("expected missing traffic log error")
	}
	if analyzer.count != 0 {
		t.Fatalf("expected analyzer not to run, got %d", analyzer.count)
	}
	if len(deadLetters.messages) != 1 || len(consumer.committed) != 1 {
		t.Fatalf("expected dead letter and commit, got dlq=%d committed=%d", len(deadLetters.messages), len(consumer.committed))
	}
}

func TestWorkerReturnsErrNoMessageWithoutMetricsChange(t *testing.T) {
	worker := NewWorker(&fakeConsumer{}, &fakeProducer{}, &fakeTrafficLogStore{}, &fakeAnalyzer{})

	err := worker.ProcessOne(context.Background())
	if !errors.Is(err, queue.ErrNoMessage) {
		t.Fatalf("expected ErrNoMessage, got %v", err)
	}
	if snapshot := worker.Metrics.Snapshot(); snapshot.Consumed != 0 || snapshot.Committed != 0 {
		t.Fatalf("unexpected metrics snapshot: %+v", snapshot)
	}
}

func testConversationMessage(t *testing.T, conversationID string) queue.Message {
	t.Helper()
	event := queue.HTTPConversationEvent{
		SchemaVersion:  queue.EventHTTPConversationV1,
		ConversationID: conversationID,
		CaptureSource:  "ebpf",
		Method:         "GET",
		Host:           "api.example.local",
		Path:           "/users/1",
		CapturedAt:     time.Now().UTC(),
	}
	envelope, err := queue.NewEnvelope(
		queue.EventHTTPConversationV1,
		queue.PayloadHTTPConversationPersistedV1,
		event,
		queue.WithEventID(queue.HTTPConversationIdempotencyKey(conversationID)),
		queue.WithIdempotencyKey(queue.HTTPConversationIdempotencyKey(conversationID)),
	)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	message, err := queue.EncodeEnvelope(queue.TopicHTTPConversations, envelope.IdempotencyKey, envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	message.Timestamp = time.Now().Add(-time.Second)
	return message
}

type fakeConsumer struct {
	messages  []queue.Message
	committed []queue.Message
	commitErr error
}

func (f *fakeConsumer) Consume(context.Context) (queue.Message, error) {
	if len(f.messages) == 0 {
		return queue.Message{}, queue.ErrNoMessage
	}
	message := f.messages[0]
	f.messages = f.messages[1:]
	return message, nil
}

func (f *fakeConsumer) Commit(_ context.Context, message queue.Message) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.committed = append(f.committed, message)
	return nil
}

func (f *fakeConsumer) Close() error {
	return nil
}

type fakeProducer struct {
	messages []queue.Message
	err      error
}

func (f *fakeProducer) Produce(_ context.Context, message queue.Message) error {
	if f.err != nil {
		return f.err
	}
	f.messages = append(f.messages, message)
	return nil
}

func (f *fakeProducer) Close() error {
	return nil
}

type fakeTrafficLogStore struct {
	logs map[string]core.TrafficLog
	err  error
}

func (f *fakeTrafficLogStore) GetTrafficLogByConversationID(_ context.Context, conversationID string) (core.TrafficLog, error) {
	if f.err != nil {
		return core.TrafficLog{}, f.err
	}
	if logEntry, ok := f.logs[conversationID]; ok {
		return logEntry, nil
	}
	return core.TrafficLog{}, errors.New("not found")
}

type fakeAnalyzer struct {
	count int
	last  core.TrafficLog
}

func (f *fakeAnalyzer) ProcessLog(logEntry core.TrafficLog) {
	f.count++
	f.last = logEntry
}
