//go:build integration

package nucleiscanner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/scanner"
)

func TestExecuteScanContextDetectsBrokenAuthOnVulnerableLocalAPI(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local TCP listener is unavailable in this environment: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/v1/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":     "success",
			"auth_token": "test-token",
		})
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := New(scanner.DefaultTemplateRegistry()).ExecuteScanContext(ctx, core.ScanConfig{
		TargetURL:           server.URL,
		Method:              http.MethodPost,
		Path:                "/users/v1/login",
		Body:                `{"username":"tracer","password":"password"}`,
		TestType:            "BROKEN_USER_AUTH",
		RateLimitPerSecond:  5,
		TemplateConcurrency: 1,
		HostConcurrency:     1,
		PayloadConcurrency:  1,
		ProbeConcurrency:    1,
	})
	if err != nil {
		t.Fatalf("execute scan: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one vulnerable result")
	}
	if !results[0].Vulnerable {
		t.Fatalf("expected vulnerable result, got %+v", results[0])
	}
	if results[0].ResponseStatus != http.StatusOK {
		t.Fatalf("expected response status 200, got %d", results[0].ResponseStatus)
	}
}
