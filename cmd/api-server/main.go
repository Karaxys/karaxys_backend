package main

import (
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/api"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/db"
	"log"
)

func main() {
	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	database, err := db.Connect(cfg.MongoURI, cfg.MongoDBName, db.LogRetention{
		MaxEvents: cfg.TrafficLogMaxEvents,
		TTL:       cfg.TrafficLogTTL,
	})
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}
	defer database.Disconnect()

	processor := analyzer.NewProcessor(database.Client.Database(cfg.MongoDBName))
	api.NewServer(database, cfg.MongoDBName, processor).Start()
}
