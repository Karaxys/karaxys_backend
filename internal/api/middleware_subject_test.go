package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubjectFromContextReturnsAuthenticatedSubject(t *testing.T) {
	mw := NewMiddleware(10, 10, MiddlewareOptions{APIKey: "dev-api-key"})
	handler := mw.Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if SubjectFromContext(r.Context()) == "" {
			t.Fatalf("expected subject in request context")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	req.Header.Set("X-API-Key", "dev-api-key")
	handler.ServeHTTP(httptest.NewRecorder(), req)
}
