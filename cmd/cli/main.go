package main

import (
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/api"
	"karaxys_backend/internal/browser"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/proxy"
	"karaxys_backend/internal/utils"
	"log"
	"time"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	database, err := db.Connect(cfg.MongoURI, cfg.MongoDBName)
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}
	defer database.Disconnect()
	processor := analyzer.NewProcessor(database.Client.Database(cfg.MongoDBName))
	apiServer := api.NewServer(database, cfg.MongoDBName, processor)
	go func() {
		apiServer.Start()
	}()
	trafficQueue := make(chan core.TrafficLog, 1000)
	go func() {
		log.Println("Starting log processor...")
		for logEntry := range trafficQueue {
			err := database.SaveLog(logEntry)
			if err == nil {
				processor.ProcessLog(logEntry)
			}
		}
	}()
	allowedTargets := []string{
		"*",
	}

	log.Println("Proxy----")
	if err := utils.SetupGoproxyCA(cfg.CertFile, cfg.KeyFile); err != nil {
		log.Fatalf("Error: Failed to load CA certificates: %v\n", err)
	}
	log.Println("CA loaded successfully")
	srv := proxy.NewProxyServer(cfg.ProxyAddr, allowedTargets, trafficQueue)
	go func() {
		srv.Start()
	}()
	time.Sleep(1 * time.Second)

	err = browser.OpenChrome("http://"+cfg.ProxyAddr, "")
	if err != nil {
		log.Fatalf("Error: Failed to open Chrome: %v\n", err)
	}
	select {}
}
