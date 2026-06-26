package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestLoadKafkaConfigFromEnv(t *testing.T) {
	t.Setenv("KARAXYS_QUEUE_BROKERS", " redpanda:9092,127.0.0.1:19092 ")
	t.Setenv("KARAXYS_QUEUE_CLIENT_ID", " karaxys-api ")
	t.Setenv("KARAXYS_QUEUE_CONSUMER_GROUP", " karaxys-ingestor ")
	t.Setenv("KARAXYS_QUEUE_TOPICS", " karaxys.http.conversations, karaxys.analyzer.jobs ")
	t.Setenv("KARAXYS_QUEUE_TOPIC_PARTITIONS", "6")
	t.Setenv("KARAXYS_QUEUE_REPLICATION_FACTOR", "3")
	t.Setenv("KARAXYS_QUEUE_PRODUCE_TIMEOUT_SECONDS", "15")

	cfg := LoadKafkaConfigFromEnv(DefaultTopics)

	if len(cfg.Brokers) != 2 || cfg.Brokers[0] != "redpanda:9092" || cfg.Brokers[1] != "127.0.0.1:19092" {
		t.Fatalf("unexpected brokers: %#v", cfg.Brokers)
	}
	if cfg.ClientID != "karaxys-api" || cfg.ConsumerGroup != "karaxys-ingestor" {
		t.Fatalf("unexpected client/group: %#v", cfg)
	}
	if len(cfg.Topics) != 2 || cfg.Topics[0] != TopicHTTPConversations || cfg.Topics[1] != TopicAnalyzerJobs {
		t.Fatalf("unexpected topics: %#v", cfg.Topics)
	}
	if cfg.TopicPartitions != 6 || cfg.ReplicationFactor != 3 || cfg.ProduceTimeout != 15*time.Second {
		t.Fatalf("unexpected sizing config: %#v", cfg)
	}
}

func TestEnvelopeEncodeDecodePreservesMetadata(t *testing.T) {
	payload := map[string]string{"conversation_id": "6650f8cb1c5e7c6c1f93a111"}
	envelope, err := NewEnvelope(
		EventHTTPConversationV1,
		"http.conversation.v1",
		payload,
		WithEventID("event-1"),
		WithIdempotencyKey("conversation:6650f8cb1c5e7c6c1f93a111"),
		WithIdentity("tenant-1", "project-1", "agent-1", "ebpf"),
	)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}

	message, err := EncodeEnvelope(TopicHTTPConversations, envelope.IdempotencyKey, envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	if message.Headers[HeaderSchemaVersion] != EventHTTPConversationV1 || message.Headers[HeaderTenantID] != "tenant-1" {
		t.Fatalf("unexpected headers: %#v", message.Headers)
	}

	decoded, err := DecodeEnvelope(message)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if decoded.EventID != "event-1" || decoded.IdempotencyKey != "conversation:6650f8cb1c5e7c6c1f93a111" {
		t.Fatalf("unexpected decoded envelope: %#v", decoded)
	}
	var decodedPayload map[string]string
	if err := json.Unmarshal(decoded.Payload, &decodedPayload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decodedPayload["conversation_id"] != "6650f8cb1c5e7c6c1f93a111" {
		t.Fatalf("unexpected payload: %#v", decodedPayload)
	}
}

func TestScanJobEnvelopeUsesStableIdempotencyKey(t *testing.T) {
	event := ScanJobEvent{
		SchemaVersion: EventScanJobV1,
		JobID:         "6650f8cb1c5e7c6c1f93a111",
		TenantID:      "tenant-1",
		TestType:      "BROKEN_USER_AUTH",
		CreatedAt:     time.Now().UTC(),
	}
	key := ScanJobIdempotencyKey(event.JobID)
	envelope, err := NewEnvelope(
		EventScanJobV1,
		PayloadScanJobQueuedV1,
		event,
		WithEventID(key),
		WithIdempotencyKey(key),
		WithIdentity(event.TenantID, event.ProjectID, "", "active_scanner"),
	)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	message, err := EncodeEnvelope(TopicScanJobs, key, envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	if message.Topic != TopicScanJobs || message.Key != key {
		t.Fatalf("unexpected message: %#v", message)
	}
	decoded, err := DecodeEnvelope(message)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if decoded.PayloadType != PayloadScanJobQueuedV1 || decoded.IdempotencyKey != key {
		t.Fatalf("unexpected envelope: %#v", decoded)
	}
}

func TestMemoryBrokerProducesAndConsumes(t *testing.T) {
	broker := NewMemoryBroker(1)
	producer := broker.Producer()
	consumer := broker.Consumer(TopicAnalyzerJobs)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := producer.Produce(ctx, Message{Topic: TopicAnalyzerJobs, Key: "job-1", Value: []byte(`{"ok":true}`)}); err != nil {
		t.Fatalf("produce: %v", err)
	}
	message, err := consumer.Consume(ctx)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if message.Topic != TopicAnalyzerJobs || message.Key != "job-1" {
		t.Fatalf("unexpected message: %#v", message)
	}
	if err := consumer.Commit(ctx, message); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestMemoryBrokerProduceRespectsBackpressureContext(t *testing.T) {
	broker := NewMemoryBroker(1)
	producer := broker.Producer()
	ctx := context.Background()

	if err := producer.Produce(ctx, Message{Topic: TopicAnalyzerJobs, Key: "job-1", Value: []byte(`{"ok":true}`)}); err != nil {
		t.Fatalf("produce first message: %v", err)
	}
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := producer.Produce(timeoutCtx, Message{Topic: TopicAnalyzerJobs, Key: "job-2", Value: []byte(`{"ok":true}`)})
	if err == nil {
		t.Fatalf("expected produce to fail when topic buffer is full and context expires")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestKafkaConsumerDrainsPendingRecords(t *testing.T) {
	consumer := &KafkaConsumer{
		pending: []*kgo.Record{
			{
				Topic:   TopicHTTPConversations,
				Key:     []byte("conversation-1"),
				Value:   []byte(`{"id":1}`),
				Headers: []kgo.RecordHeader{{Key: HeaderSchemaVersion, Value: []byte(EventHTTPConversationV1)}},
			},
			{
				Topic: TopicHTTPConversations,
				Key:   []byte("conversation-2"),
				Value: []byte(`{"id":2}`),
			},
		},
	}

	first, err := consumer.Consume(context.Background())
	if err != nil {
		t.Fatalf("consume first pending record: %v", err)
	}
	second, err := consumer.Consume(context.Background())
	if err != nil {
		t.Fatalf("consume second pending record: %v", err)
	}

	if first.Key != "conversation-1" || first.Headers[HeaderSchemaVersion] != EventHTTPConversationV1 {
		t.Fatalf("unexpected first message: %#v", first)
	}
	if second.Key != "conversation-2" || len(consumer.pending) != 0 {
		t.Fatalf("unexpected second message or pending buffer: message=%#v pending=%d", second, len(consumer.pending))
	}
}
