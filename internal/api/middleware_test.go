package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticateRejectsMissingAPIKey(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{APIKey: "dev-api-key"})
	handler := mw.Authenticate(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthenticateRejectsWhenAPIKeyNotConfigured(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{})
	handler := mw.Authenticate(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthenticateAcceptsAPIKeyAndBearerToken(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{APIKey: "dev-api-key"})
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subject, ok := r.Context().Value(subjectContextKey).(string); !ok || subject == "" {
			t.Fatalf("expected authenticated subject in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, header := range []struct {
		name  string
		value string
	}{
		{name: "X-API-Key", value: "dev-api-key"},
		{name: "Authorization", value: "Bearer dev-api-key"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
		req.Header.Set(header.name, header.value)

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: unexpected status: got=%d body=%s", header.name, rec.Code, rec.Body.String())
		}
	}
}

func TestAuthenticateAcceptsSessionToken(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{
		SessionAuth: func(token string) (*Principal, bool) {
			if token != "session-token" {
				return nil, false
			}
			return &Principal{
				ActorType: "user",
				UserID:    "user-1",
				AccountID: "account-1",
				Role:      "admin",
			}, true
		},
	})
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.UserID != "user-1" || principal.AccountID != "account-1" {
			t.Fatalf("expected user principal in context, got %+v", principal)
		}
		if SubjectFromContext(r.Context()) != "user:user-1" {
			t.Fatalf("unexpected subject: %s", SubjectFromContext(r.Context()))
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	req.Header.Set("Authorization", "Bearer session-token")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthenticateExemptsIngestionPath(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{})
	handler := mw.Authenticate(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", nil)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthenticateExemptsPublicAuthAndAgentRegistrationPaths(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{})
	handler := mw.Authenticate(okHandler())

	for _, path := range []string{"/auth/signup", "/auth/login", "/auth/refresh", "/agents/register"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: unexpected status: got=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestCORSAllowsConfiguredOriginAndRejectsUnknown(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{
		APIKey:         "dev-api-key",
		AllowedOrigins: []string{"https://dashboard.example.local"},
	})
	handler := mw.CORS(okHandler())

	allowedRec := httptest.NewRecorder()
	allowedReq := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	allowedReq.Header.Set("Origin", "https://dashboard.example.local")
	handler.ServeHTTP(allowedRec, allowedReq)

	if allowedRec.Code != http.StatusNoContent {
		t.Fatalf("allowed origin status: got=%d body=%s", allowedRec.Code, allowedRec.Body.String())
	}
	if got := allowedRec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.local" {
		t.Fatalf("unexpected allow origin header: %s", got)
	}

	blockedRec := httptest.NewRecorder()
	blockedReq := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	blockedReq.Header.Set("Origin", "https://evil.example")
	handler.ServeHTTP(blockedRec, blockedReq)

	if blockedRec.Code != http.StatusForbidden {
		t.Fatalf("blocked origin status: got=%d body=%s", blockedRec.Code, blockedRec.Body.String())
	}
}

func TestSecureHeaders(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{APIKey: "dev-api-key"})
	handler := mw.SecureHeaders(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff header")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing frame deny header")
	}
}

func TestLimitWriteBodyLimitsNonIngestionWrites(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{
		APIKey:            "dev-api-key",
		MaxWriteBodyBytes: 4,
	})
	handler := mw.LimitWriteBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader("12345"))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}

	ingestRec := httptest.NewRecorder()
	ingestReq := httptest.NewRequest(http.MethodPost, "/v1/ingest/conversations", strings.NewReader("12345"))
	handler.ServeHTTP(ingestRec, ingestReq)

	if ingestRec.Code != http.StatusNoContent {
		t.Fatalf("ingestion path should be exempt from middleware body limit, got=%d", ingestRec.Code)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}
