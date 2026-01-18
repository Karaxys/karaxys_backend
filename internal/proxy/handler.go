package proxy
import(
	"fmt"
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
	"karaxys_backend/internal/core"
	"github.com/elazarl/goproxy"
)

const MaxLogSize = 10 * 1024
const MaxReadSize = 50 * 1024 * 1024

func sanitizeBody(data []byte) string{
	if len(data) == 0{
		return ""
	}
	if !utf8.Valid(data){
		return "[BINARY DATA]"
	}
	if len(data) > MaxLogSize{
		return string(data[:MaxLogSize]) + "...[TRUNCATED]"
	}
	return string(data)
}

func HandleRequest(queue chan<- core.TrafficLog) goproxy.ReqHandler{
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
		req.Header.Del("Accept-Encoding")
		var bodyBytes []byte
		if req.Body!=nil{
			bodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, MaxReadSize))
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
		reqBodyStr := sanitizeBody(bodyBytes)

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

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		isBinaryType := strings.Contains(ct, "image") || strings.Contains(ct, "video") || strings.Contains(ct, "audio") || strings.Contains(ct, "application/octet-stream") || strings.Contains(ct, "font") || strings.Contains(ct, "pdf") || strings.Contains(ct, "zip") || strings.Contains(ct, "gzip")
		var bodyBytes []byte
		if !isBinaryType && resp.Body!=nil{
			bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, MaxReadSize))
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		if bodyBytes != nil{
			resp.ContentLength = int64(len(bodyBytes))
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
			resp.Header.Del("Transfer-Encoding")
		}

		logData.RespStatus = resp.Status
		if isBinaryType{
			logData.RespBody = "[BINARY DATA: " + ct + "]"
		}else{
			logData.RespBody = sanitizeBody(bodyBytes)
		}

		select {
		case queue <- logData:
		default:
			fmt.Println("Warning: Queue is full, dropping log")
		}

		return resp
	})
}