package main

import (
	"context"
	"flag"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/deadletter"
	"karaxys_backend/internal/queue"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	workerID := flag.String("worker-id", hostnameDefault("karaxys-dead-letter-consumer"), "Dead-letter consumer instance id")
	flag.Parse()

	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	if err := config.ValidateProductionEnvironment(config.ServiceDeadLetterConsumer); err != nil {
		log.Fatalf("Invalid production environment: %v", err)
	}

	database, err := db.Connect(cfg.MongoURI, cfg.MongoDBName, db.LogRetention{
		MaxEvents: cfg.TrafficLogMaxEvents,
		TTL:       cfg.TrafficLogTTL,
	})
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}
	defer database.Disconnect()

	queueCfg := queue.LoadKafkaConfigFromEnv([]string{queue.TopicIngestDeadLetter})
	if group := strings.TrimSpace(os.Getenv("KARAXYS_DEAD_LETTER_CONSUMER_GROUP")); group != "" {
		queueCfg.ConsumerGroup = group
	} else {
		queueCfg.ConsumerGroup = "karaxys-dead-letter-consumer"
	}
	queueCfg.ClientID = queueCfg.ClientID + "-dead-letter-consumer"

	queueConsumer, err := queue.NewKafkaConsumer(queueCfg)
	if err != nil {
		log.Fatalf("Error creating dead-letter queue consumer: %v", err)
	}
	consumer := deadletter.NewConsumer(queueConsumer, database)
	defer func() {
		if err := consumer.Close(); err != nil {
			log.Printf("Dead-letter consumer close error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf(
		"Dead-letter consumer started. worker_id=%s brokers=%s group=%s topic=%s",
		*workerID,
		strings.Join(queueCfg.Brokers, ","),
		queueCfg.ConsumerGroup,
		queue.TopicIngestDeadLetter,
	)
	if err := consumer.Run(ctx); err != nil {
		log.Fatalf("Dead-letter consumer stopped with error: %v", err)
	}
	log.Printf("Dead-letter consumer stopped. worker_id=%s", *workerID)
}

func hostnameDefault(fallback string) string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return fallback
	}
	return hostname
}
