package queue

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type KafkaProducer struct {
	client         *kgo.Client
	produceTimeout time.Duration
}

type KafkaConsumer struct {
	client  *kgo.Client
	pending []*kgo.Record
}

func NewKafkaProducer(cfg KafkaConfig) (*KafkaProducer, error) {
	client, err := newKafkaClient(cfg,
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
	)
	if err != nil {
		return nil, err
	}
	timeout := cfg.ProduceTimeout
	if timeout <= 0 {
		timeout = defaultProduceTimeout
	}
	return &KafkaProducer{client: client, produceTimeout: timeout}, nil
}

func NewKafkaConsumer(cfg KafkaConfig) (*KafkaConsumer, error) {
	group := strings.TrimSpace(cfg.ConsumerGroup)
	if group == "" {
		group = defaultConsumerGroup
	}
	topics := normalizedTopics(cfg.Topics)
	if len(topics) == 0 {
		topics = DefaultTopics
	}
	client, err := newKafkaClient(cfg,
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topics...),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		return nil, err
	}
	return &KafkaConsumer{client: client}, nil
}

func (p *KafkaProducer) Produce(ctx context.Context, message Message) error {
	if p == nil || p.client == nil {
		return fmt.Errorf("kafka producer is not configured")
	}
	if strings.TrimSpace(message.Topic) == "" {
		return fmt.Errorf("message topic is required")
	}
	produceCtx := ctx
	cancel := func() {}
	if p.produceTimeout > 0 {
		produceCtx, cancel = context.WithTimeout(ctx, p.produceTimeout)
	}
	defer cancel()

	record := &kgo.Record{
		Topic:     message.Topic,
		Key:       []byte(message.Key),
		Value:     message.Value,
		Headers:   kafkaHeaders(message.Headers),
		Timestamp: message.Timestamp,
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}
	return p.client.ProduceSync(produceCtx, record).FirstErr()
}

func (p *KafkaProducer) Close() error {
	if p == nil || p.client == nil {
		return nil
	}
	p.client.Close()
	return nil
}

func (c *KafkaConsumer) Consume(ctx context.Context) (Message, error) {
	if c == nil {
		return Message{}, fmt.Errorf("kafka consumer is not configured")
	}
	if message, ok := c.nextPending(); ok {
		return message, nil
	}
	if c.client == nil {
		return Message{}, fmt.Errorf("kafka consumer is not configured")
	}
	fetches := c.client.PollFetches(ctx)
	if ctx.Err() != nil {
		return Message{}, ctx.Err()
	}
	if errs := fetches.Errors(); len(errs) > 0 {
		return Message{}, errs[0].Err
	}
	iter := fetches.RecordIter()
	if iter.Done() {
		return Message{}, ErrNoMessage
	}
	for !iter.Done() {
		c.pending = append(c.pending, iter.Next())
	}
	return c.nextPendingOrNoMessage()
}

func (c *KafkaConsumer) Commit(ctx context.Context, message Message) error {
	if c == nil || c.client == nil {
		return nil
	}
	record, ok := message.AckToken.(*kgo.Record)
	if !ok || record == nil {
		return fmt.Errorf("kafka commit requires a record ack token")
	}
	return c.client.CommitRecords(ctx, record)
}

func (c *KafkaConsumer) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	c.client.Close()
	return nil
}

func (c *KafkaConsumer) nextPendingOrNoMessage() (Message, error) {
	message, ok := c.nextPending()
	if !ok {
		return Message{}, ErrNoMessage
	}
	return message, nil
}

func (c *KafkaConsumer) nextPending() (Message, bool) {
	if len(c.pending) == 0 {
		return Message{}, false
	}
	record := c.pending[0]
	c.pending[0] = nil
	c.pending = c.pending[1:]
	return recordToMessage(record), true
}

func newKafkaClient(cfg KafkaConfig, extraOptions ...kgo.Opt) (*kgo.Client, error) {
	brokers := normalizedTopics(cfg.Brokers)
	if len(brokers) == 0 {
		brokers = []string{defaultBrokerAddr}
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		clientID = "karaxys-backend"
	}
	options := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ClientID(clientID),
	}
	options = append(options, extraOptions...)
	return kgo.NewClient(options...)
}

func kafkaHeaders(headers map[string]string) []kgo.RecordHeader {
	if len(headers) == 0 {
		return nil
	}
	out := make([]kgo.RecordHeader, 0, len(headers))
	for key, value := range headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out = append(out, kgo.RecordHeader{Key: key, Value: []byte(value)})
	}
	return out
}

func messageHeaders(headers []kgo.RecordHeader) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for _, header := range headers {
		if strings.TrimSpace(header.Key) == "" {
			continue
		}
		out[header.Key] = string(header.Value)
	}
	return out
}

func recordToMessage(record *kgo.Record) Message {
	if record == nil {
		return Message{}
	}
	return Message{
		Topic:     record.Topic,
		Key:       string(record.Key),
		Value:     record.Value,
		Headers:   messageHeaders(record.Headers),
		Timestamp: record.Timestamp,
		AckToken:  record,
	}
}

func normalizedTopics(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
