package proxy
import(
	"fmt"
	"log"
	"net/http"
	"regexp"
	"karaxys_backend/internal/core"
	"github.com/elazarl/goproxy"
)

type ProxyServer struct {
	Addr         string
	AllowedHosts []string
	Server	   *goproxy.ProxyHttpServer
	Queue        chan core.TrafficLog
}

func NewProxyServer(addr string, allowedHosts []string, queue chan core.TrafficLog) *ProxyServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest(RequestFilter(allowedHosts)).Do(HandleRequest(queue))
	proxy.OnResponse(RequestFilter(allowedHosts)).Do(HandleResponse(queue))

	return &ProxyServer{
		Addr:         addr,
		AllowedHosts: allowedHosts,
		Server:       proxy,
		Queue:		  queue,
	}
}

func (p *ProxyServer) Start() {
	fmt.Printf("Proxy started on %s\n", p.Addr)
	fmt.Printf("Monitoring Traffic for: %v\n", p.AllowedHosts)

	log.Fatal(http.ListenAndServe(p.Addr, p.Server))
}
