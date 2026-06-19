package main

import (
	"context"
	"errors"
	"flag"
	"karaxys_backend/internal/api"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/queue"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", envDefault("KARAXYS_INGESTOR_ADDR", ":8082"), "Ingestor listen address")
	flag.Parse()

	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	if err := config.ValidateProductionEnvironment(config.ServiceIngestor); err != nil {
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
	queueCfg.ClientID = queueCfg.ClientID + "-ingestor"
	producer, err := queue.NewKafkaProducer(queueCfg)
	if err != nil {
		log.Fatalf("Error creating conversation queue producer: %v", err)
	}
	defer producer.Close()

	service := ingest.NewService(database, nil, os.Getenv("KARAXYS_AGENT_TOKEN"), ingest.MongoAgentAuthenticator(database))
	service.Publisher = ingest.NewQueuePublisher(producer)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ingest/conversations", service.HandleConversation)

	mw := api.NewMiddleware(100, 200, api.MiddlewareOptions{
		AllowedOrigins:    splitCSVEnv("KARAXYS_ALLOWED_ORIGINS", []string{"http://localhost:7000"}),
		MaxWriteBodyBytes: int64EnvDefault("KARAXYS_MAX_WRITE_BYTES", api.DefaultMaxWriteBodyBytes),
	})
	handler := mw.SecureHeaders(mw.CORS(mw.Recoverer(mw.Logger(mw.RateLimit(mw.LimitWriteBody(mux))))))
	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Ingestor running on %s", *addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Fatalf("Ingestor shutdown failed: %v", err)
		}
		if err := <-errCh; err != nil {
			log.Fatalf("Ingestor stopped with error: %v", err)
		}
	case err := <-errCh:
		if err != nil {
			log.Fatalf("Ingestor stopped with error: %v", err)
		}
	}
	log.Println("Ingestor stopped")
}

func splitCSVEnv(key string, fallback []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	var values []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		return fallback
	}
	return values
}

func int64EnvDefault(key string, fallback int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envDefault(key string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
