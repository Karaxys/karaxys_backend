package proxy
import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"github.com/elazarl/goproxy"
)

type ProxyServer struct {
	Addr         string
	AllowedHosts []string
	Server       *goproxy.ProxyHttpServer
}

func NewProxyServer(addr string, allowedHosts []string) *ProxyServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest(RequestFilter(allowedHosts)).DoFunc(HandleRequest)
	proxy.OnResponse(RequestFilter(allowedHosts)).DoFunc(HandleResponse)

	return &ProxyServer{
		Addr:         addr,
		AllowedHosts: allowedHosts,
		Server:       proxy,
	}
}

func (p *ProxyServer) Start() {
	fmt.Printf("Proxy started on %s\n", p.Addr)
	fmt.Printf("Monitoring Traffic for: %v\n", p.AllowedHosts)

	log.Fatal(http.ListenAndServe(p.Addr, p.Server))
}
