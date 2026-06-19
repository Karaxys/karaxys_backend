package main

import (
	"context"
	"flag"
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/queue"
	"karaxys_backend/internal/runtimeanalyzer"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	workerID := flag.String("worker-id", hostnameDefault("karaxys-runtime-analyzer"), "Runtime analyzer worker instance id")
	metricsInterval := flag.Duration("metrics-interval", 30*time.Second, "Runtime analyzer metrics log interval")
	flag.Parse()

	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	if err := config.ValidateProductionEnvironment(config.ServiceRuntimeAnalyzer); err != nil {
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

	queueCfg := queue.LoadKafkaConfigFromEnv([]string{queue.TopicHTTPConversations})
	if group := strings.TrimSpace(os.Getenv("KARAXYS_RUNTIME_ANALYZER_CONSUMER_GROUP")); group != "" {
		queueCfg.ConsumerGroup = group
	}
	queueCfg.ClientID = queueCfg.ClientID + "-runtime-analyzer"

	consumer, err := queue.NewKafkaConsumer(queueCfg)
	if err != nil {
		log.Fatalf("Error creating queue consumer: %v", err)
	}
	deadLetterProducer, err := queue.NewKafkaProducer(queueCfg)
	if err != nil {
		_ = consumer.Close()
		log.Fatalf("Error creating dead-letter queue producer: %v", err)
	}

	processor := analyzer.NewProcessor(database.Client.Database(cfg.MongoDBName))
	worker := runtimeanalyzer.NewWorker(consumer, deadLetterProducer, database, processor)
	defer func() {
		if err := worker.Close(); err != nil {
			log.Printf("Runtime analyzer close error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *metricsInterval > 0 {
		go logMetrics(ctx, worker.Metrics, *metricsInterval)
	}

	log.Printf(
		"Runtime analyzer started. worker_id=%s brokers=%s group=%s topic=%s",
		*workerID,
		strings.Join(queueCfg.Brokers, ","),
		queueCfg.ConsumerGroup,
		queue.TopicHTTPConversations,
	)
	if err := worker.Run(ctx); err != nil {
		log.Fatalf("Runtime analyzer stopped with error: %v", err)
	}
	log.Printf("Runtime analyzer stopped. worker_id=%s", *workerID)
}

func logMetrics(ctx context.Context, metrics *runtimeanalyzer.Metrics, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot := metrics.Snapshot()
			log.Printf(
				"runtime_analyzer_metrics consumed=%d processed=%d failed=%d retried=%d dead_lettered=%d committed=%d last_lag=%s max_lag=%s",
				snapshot.Consumed,
				snapshot.Processed,
				snapshot.Failed,
				snapshot.Retried,
				snapshot.DeadLettered,
				snapshot.Committed,
				snapshot.LastLag,
				snapshot.MaxLag,
			)
		}
	}
}

func hostnameDefault(fallback string) string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return fallback
	}
	return hostname
}
