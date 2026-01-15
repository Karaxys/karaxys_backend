package main

import(
	"log"
	"time"
	"vuln_scanner/internal/browser"
	"vuln_scanner/internal/proxy"
	"vuln_scanner/internal/utils"
	"vuln_scanner/internal/core"
	"vuln_scanner/internal/db"
	"vuln_scanner/internal/config"
	"vuln_scanner/internal/analyzer"
)
func main(){
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
	trafficQueue := make(chan core.TrafficLog, 1000)
	go func(){
		log.Println("Starting log processor...")
		for logEntry := range trafficQueue{
			err := database.SaveLog(logEntry)
			if err == nil{
				processor.ProcessLog(logEntry)
			}
		}
	}()
	allowedTargets:= []string{
		"*",
	}

	log.Println("Proxy----")
	if err := utils.SetupGoproxyCA(cfg.CertFile, cfg.KeyFile); err != nil{
		log.Fatalf("Error: Failed to load CA certificates: %v\n", err)
	}
	log.Println("CA loaded successfully")
	srv := proxy.NewProxyServer(cfg.ProxyAddr, allowedTargets, trafficQueue)
	go func(){
		srv.Start()
	}()
	time.Sleep(1*time.Second)

	err = browser.OpenChrome("http://"+cfg.ProxyAddr, "")
	if err != nil {
		log.Fatalf("Error: Failed to open Chrome: %v\n", err)
	}
	select{}
}