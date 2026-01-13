package proxy

import(
	"net/http"
	"strings"
	"github.com/elazarl/goproxy"
)

var BlockList = []string{
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "googleusercontent.com",
    "mozilla.org",
    "firefox.com",
    "gvt1.com",
}

func isAllowedHost(host string, allowedHosts []string) bool{
	if idx := strings.Index(host, ":"); idx != -1{
		host = host[:idx]
	}

	for _, blocked := range BlockList{
        if strings.HasSuffix(host, blocked){
            return false
        }
    }

	for _, allowed := range allowedHosts{
		if allowed == "*"{
			return true
		}
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