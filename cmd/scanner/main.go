package main

import(
	"log"
	"vuln_scanner/internal/proxy"
	"vuln_scanner/internal/utils"
	"vuln_scanner/internal/core"
)
func main(){
	proxyAddr := "127.0.0.1:8080"
	certFile := "certs/ca.pem"
	keyFile := "certs/ca.key"

	trafficQueue := make(chan core.TrafficLog, 1000)
	go func(){
		for logEntry := range trafficQueue{
			log.Printf("Logged %s request to %s with response status %s and response length %d\n", logEntry.Method, logEntry.URL, logEntry.RespStatus, len(logEntry.RespBody))
		}
	}()
	allowedTargets:= []string{
		"testphp.vulnweb.com",
		"juice-shop.herokuapp.com",
	}

	log.Println("Proxy----")
	if err := utils.SetupGoproxyCA(certFile, keyFile); err != nil{
		log.Fatalf("Error: Failed to load CA certificates: %v\n", err)
	}
	log.Println("CA loaded successfully")
	srv := proxy.NewProxyServer(proxyAddr, allowedTargets, trafficQueue)
	srv.Start()
}