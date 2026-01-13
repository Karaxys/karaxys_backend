package proxy
import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"vuln_scanner/internal/core"
	"github.com/elazarl/goproxy"
)

const MaxBodySize = 10 * 1024

func HandleRequest(queue chan<- core.TrafficLog) goproxy.ReqHandler{
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
		var bodyBytes []byte
		if req.Body!=nil{
			bodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, MaxBodySize))
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		logData := core.TrafficLog{
			Method:    req.Method,
			URL:       req.URL.String(),
			Host:      req.URL.Host,
			Path:      req.URL.Path,
			ReqHeaders: req.Header,
			ReqBody:   string(bodyBytes),
		}
		ctx.UserData = logData
		return req, nil
	})
}

func HandleResponse(queue chan<- core.TrafficLog) goproxy.RespHandler{
	return goproxy.FuncRespHandler(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response{
		if resp == nil{
			return nil
		}

		logData, ok := ctx.UserData.(core.TrafficLog)
		if !ok{
			return resp
		}
		var bodyBytes []byte
		if resp.Body!=nil{
			bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		logData.RespStatus = resp.Status
		logData.RespBody = string(bodyBytes)

		select {
		case queue <- logData:
		default:
			fmt.Println("Warning: Queue is full, dropping log")
		}

		return resp
	})
}