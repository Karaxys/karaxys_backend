package proxy
import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"vuln_scanner/internal/core"
	"github.com/elazarl/goproxy"
)

const MaxLogSize = 10 * 1024
const MaxReadSize = 50 * 1024 * 1024

func HandleRequest(queue chan<- core.TrafficLog) goproxy.ReqHandler{
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
		req.Header.Del("Accept-Encoding")
		var bodyBytes []byte
		if req.Body!=nil{
			bodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, MaxReadSize))
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		reqBodyStr := string(bodyBytes)
		if len(reqBodyStr) > MaxLogSize {
			reqBodyStr = reqBodyStr[:MaxLogSize] + "...[TRUNCATED]"
		}

		logData := core.TrafficLog{
			Method:    req.Method,
			URL:       req.URL.String(),
			Host:      req.URL.Host,
			Path:      req.URL.Path,
			ReqHeaders: req.Header,
			ReqBody:   reqBodyStr,
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
			bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, MaxReadSize))
			resp.Body.Close()
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
		resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		resp.Header.Del("Transfer-Encoding")

		logData.RespStatus = resp.Status
		if len(bodyBytes) > 0{
			respBodyStr := string(bodyBytes)
			if len(respBodyStr) > MaxLogSize{
				respBodyStr = respBodyStr[:MaxLogSize] + "...[TRUNCATED]"
			}
			logData.RespBody = respBodyStr
		} else {
			logData.RespBody = "[Empty]"
		}

		select {
		case queue <- logData:
		default:
			fmt.Println("Warning: Queue is full, dropping log")
		}

		return resp
	})
}