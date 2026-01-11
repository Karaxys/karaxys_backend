package proxy
import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"github.com/elazarl/goproxy"
)

func HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	fmt.Printf("[INTERCEPTED REQUEST] %s %s\nHeaders: %#v\n", req.Method, req.URL.String(), req.Header)

	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			fmt.Printf("Error reading request body: %v\n", err)
			return req, nil
		}
		if len(bodyBytes) > 0 {
			fmt.Printf("Request Body: %s\n", string(bodyBytes))
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return req, nil
}

func HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		return resp
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return resp
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	fmt.Printf("[INTERCEPTED RESPONSE] %s %s\nStatus: %s\nHeaders: %#v\n", ctx.Req.Method, ctx.Req.URL.String(), resp.Status, resp.Header)
	if len(bodyBytes) > 0 {
		fmt.Printf("Response Body: %s\n", string(bodyBytes))
	}

	return resp
}