package utils

import(
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/elazarl/goproxy"
	"os"
)

func SetupGoproxyCA(certpath, keypath string) error {
	if _, err := os.Stat(certpath); os.IsNotExist(err) {
		return fmt.Errorf("certificate file does not exist: %s", certpath)
	}
	if _, err := os.Stat(keypath); os.IsNotExist(err) {
		return fmt.Errorf("key file does not exist: %s", keypath)
	}

	cert, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		return fmt.Errorf("failed to load keypair: %w", err)
	}
	if cert.Leaf == nil {
		x509Cert, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr != nil {
			return fmt.Errorf("failed to parse certificate: %w", parseErr)
		}
		cert.Leaf = x509Cert
	}

	goproxy.GoproxyCa = cert
	ca := &goproxy.GoproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	return nil
}
