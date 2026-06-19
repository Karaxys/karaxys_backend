package queue

import (
	"context"
	"reflect"
	"sync"
)

type MemoryBroker struct {
	mu     sync.Mutex
	topics map[string]chan Message
	size   int
	closed bool
}

type MemoryProducer struct {
	broker *MemoryBroker
}

type MemoryConsumer struct {
	broker *MemoryBroker
	topics []string
}

func NewMemoryBroker(size int) *MemoryBroker {
	if size <= 0 {
		size = 1000
	}
	return &MemoryBroker{
		topics: make(map[string]chan Message),
		size:   size,
	}
}

func (b *MemoryBroker) Producer() *MemoryProducer {
	return &MemoryProducer{broker: b}
}

func (b *MemoryBroker) Consumer(topics ...string) *MemoryConsumer {
	return &MemoryConsumer{broker: b, topics: topics}
}

func (p *MemoryProducer) Produce(ctx context.Context, message Message) error {
	if p == nil || p.broker == nil {
		return context.Canceled
	}
	topic := p.broker.topic(message.Topic)
	select {
	case topic <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *MemoryProducer) Close() error {
	return nil
}

func (c *MemoryConsumer) Consume(ctx context.Context) (Message, error) {
	if c == nil || c.broker == nil || len(c.topics) == 0 {
		return Message{}, ErrNoMessage
	}
	cases := make([]reflect.SelectCase, 0, len(c.topics)+1)
	for _, topicName := range c.topics {
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(c.broker.topic(topicName)),
		})
	}
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})

	chosen, value, ok := reflect.Select(cases)
	if chosen == len(cases)-1 {
		return Message{}, ctx.Err()
	}
	if !ok {
		return Message{}, ErrNoMessage
	}
	return value.Interface().(Message), nil
}

func (c *MemoryConsumer) Commit(ctx context.Context, message Message) error {
	return ctx.Err()
}

func (c *MemoryConsumer) Close() error {
	return nil
}

func (b *MemoryBroker) topic(name string) chan Message {
	name = NormalizeTopic(name)
	b.mu.Lock()
	defer b.mu.Unlock()
	if topic, ok := b.topics[name]; ok {
		return topic
	}
	topic := make(chan Message, b.size)
	b.topics[name] = topic
	return topic
}
