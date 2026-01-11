package proxy

import(
	"net/http"
	"strings"
	"github.com/elazarl/goproxy"
)

func isAllowedHost(host string, allowedHosts []string) bool{
	if idx := strings.Index(host, ":"); idx != -1{
		host = host[:idx]
	}

	for _, allowed := range allowedHosts{
		if host == allowed || strings.HasSuffix(host, "."+allowed){
			return true
		}
	}
	return false
}

func RequestFilter(allowedHosts []string) goproxy.ReqConditionFunc{
	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool{
		return isAllowedHost(req.URL.Host, allowedHosts)
	}
}