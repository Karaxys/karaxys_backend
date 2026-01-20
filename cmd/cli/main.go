package main

import(
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/browser"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/proxy"
	"karaxys_backend/internal/scanner"
	"karaxys_backend/internal/utils"
	"log"
	"strings"
	"time"
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
	vulnScanner := scanner.NewScanner()
	trafficQueue := make(chan core.TrafficLog, 1000)
	go func(){
		log.Println("Starting log processor...")
		for logEntry := range trafficQueue{
			err := database.SaveLog(logEntry)
			if err == nil{
				processor.ProcessLog(logEntry)
			}
			if (logEntry.Method == "PATCH" || logEntry.Method == "PUT") &&
				strings.Contains(logEntry.Path, "/rest/products/reviews"){
				log.Println("INTERCEPTED TARGET REQUEST! Triggering BOLA Scan...")
				attackerToken := "Bearer eyJ0eX....."
				scanCfg := scanner.ScanConfig{
					TargetURL:  "http://" + logEntry.Host, // e.g. http://localhost:3000
					Method:     logEntry.Method,
					Path:       logEntry.Path,    // e.g. /rest/products/reviews/5
					Body:       logEntry.ReqBody, // The original body (User A's update)
					TestType:   "BOLA",
					ManualAuth: attackerToken, // We inject User B's token
				}

				// Run the scan in a separate goroutine so we don't block the proxy
				go func(cfg scanner.ScanConfig) {
					results, err := vulnScanner.ExecuteScan(cfg)
					if err != nil {
						log.Printf("Scan Failed: %v", err)
						return
					}

					// Print Results
					if len(results) > 0 {
						for _, r := range results {
							if r.Vulnerable {
								log.Printf("\n VULNERABILITY CONFIRMED \nType: %s\nProof: %s\n", r.TestType, r.Description)
							} else {
								log.Printf("\n Scan Completed (Secure/Error): %s\n", r.Description)
							}
						}
					} else {
						log.Println("Scan Finished. No matches (Check template config).")
					}
				}(scanCfg)
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