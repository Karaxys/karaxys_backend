package queue

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBrokerAddr        = "127.0.0.1:19092"
	defaultConsumerGroup     = "karaxys-runtime-analyzer"
	defaultTopicPartitions   = 3
	defaultReplicationFactor = 1
	defaultProduceTimeout    = 10 * time.Second
)

type KafkaConfig struct {
	Brokers           []string
	ClientID          string
	ConsumerGroup     string
	Topics            []string
	TopicPartitions   int32
	ReplicationFactor int16
	ProduceTimeout    time.Duration
}

func LoadKafkaConfigFromEnv(defaultTopics []string) KafkaConfig {
	return KafkaConfig{
		Brokers:           splitCSVEnv("KARAXYS_QUEUE_BROKERS", []string{defaultBrokerAddr}),
		ClientID:          envDefault("KARAXYS_QUEUE_CLIENT_ID", "karaxys-backend"),
		ConsumerGroup:     envDefault("KARAXYS_QUEUE_CONSUMER_GROUP", defaultConsumerGroup),
		Topics:            splitCSVEnv("KARAXYS_QUEUE_TOPICS", defaultTopics),
		TopicPartitions:   int32EnvDefault("KARAXYS_QUEUE_TOPIC_PARTITIONS", defaultTopicPartitions),
		ReplicationFactor: int16EnvDefault("KARAXYS_QUEUE_REPLICATION_FACTOR", defaultReplicationFactor),
		ProduceTimeout:    durationSecondsEnvDefault("KARAXYS_QUEUE_PRODUCE_TIMEOUT_SECONDS", defaultProduceTimeout),
	}
}

func splitCSVEnv(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string(nil), fallback...)
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), fallback...)
	}
	return out
}

func envDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func int32EnvDefault(key string, fallback int32) int32 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || value <= 0 {
		return fallback
	}
	return int32(value)
}

func int16EnvDefault(key string, fallback int16) int16 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 16)
	if err != nil || value <= 0 {
		return fallback
	}
	return int16(value)
}

func durationSecondsEnvDefault(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Second
}
