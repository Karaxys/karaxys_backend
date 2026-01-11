package main

import(
	"log"
	"vuln_scanner/internal/proxy"
	"vuln_scanner/internal/utils"
)
func main(){
	proxyAddr := ":8080"
	certFile := "certs/ca.pem"
	keyFile := "certs/ca.key"

	allowedTargets:= []string{
		"testphp.vulnweb.com",
		"juice-shop.herokuapp.com",
	}

	log.Println("Proxy----")
	if err := utils.SetupGoproxyCA(certFile, keyFile); err != nil{
		log.Fatalf("Error: Failed to load CA certificates: %v\n", err)
	}
	log.Println("CA loaded successfully")
	srv := proxy.NewProxyServer(proxyAddr, allowedTargets)
	srv.Start()
}