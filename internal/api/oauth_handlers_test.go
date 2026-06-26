package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"karaxys_backend/internal/core"
)

func TestProviderOAuthConfigUnconfigured(t *testing.T) {
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_ID", "")
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_SECRET", "")
	if _, ok := providerOAuthConfig(core.OAuthProviderGoogle); ok {
		t.Fatal("expected google provider to be unconfigured")
	}
}

func TestProviderOAuthConfigConfigured(t *testing.T) {
	t.Setenv("KARAXYS_OAUTH_REDIRECT_BASE_URL", "https://api.example.com")
	t.Setenv("KARAXYS_OAUTH_GITHUB_CLIENT_ID", "abc")
	t.Setenv("KARAXYS_OAUTH_GITHUB_CLIENT_SECRET", "def")
	cfg, ok := providerOAuthConfig(core.OAuthProviderGitHub)
	if !ok {
		t.Fatal("expected github provider to be configured")
	}
	if cfg.RedirectURL != "https://api.example.com/auth/oauth/github/callback" {
		t.Fatalf("unexpected redirect URL: %s", cfg.RedirectURL)
	}
	if cfg.ClientID != "abc" {
		t.Fatalf("unexpected client id: %s", cfg.ClientID)
	}
}

func TestHandleOAuthStartUnconfiguredReturns503(t *testing.T) {
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_ID", "")
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_SECRET", "")
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
	req.SetPathValue("provider", core.OAuthProviderGoogle)
	rec := httptest.NewRecorder()
	s.handleOAuthStart(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestHandleOAuthStartUnsupportedProvider(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/twitter", nil)
	req.SetPathValue("provider", "twitter")
	rec := httptest.NewRecorder()
	s.handleOAuthStart(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleOAuthStartConfiguredRedirectsAndSetsState(t *testing.T) {
	t.Setenv("KARAXYS_OAUTH_REDIRECT_BASE_URL", "https://api.example.com")
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_ID", "client-id")
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_SECRET", "client-secret")
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
	req.SetPathValue("provider", core.OAuthProviderGoogle)
	rec := httptest.NewRecorder()
	s.handleOAuthStart(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, googleOAuthEndpoint.AuthURL) {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("expected oauth state cookie to be set")
	}
	if !stateCookie.HttpOnly {
		t.Fatal("oauth state cookie must be HttpOnly")
	}
	if !strings.HasPrefix(stateCookie.Value, core.OAuthProviderGoogle+":") {
		t.Fatalf("state cookie should bind provider, got %s", stateCookie.Value)
	}
}

func TestHandleOAuthCallbackInvalidStateRedirectsToLogin(t *testing.T) {
	t.Setenv("KARAXYS_OAUTH_REDIRECT_BASE_URL", "https://api.example.com")
	t.Setenv("KARAXYS_DASHBOARD_URL", "https://app.example.com")
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_ID", "client-id")
	t.Setenv("KARAXYS_OAUTH_GOOGLE_CLIENT_SECRET", "client-secret")
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=abc&state=evil", nil)
	req.SetPathValue("provider", core.OAuthProviderGoogle)
	// No matching state cookie set -> CSRF check must fail.
	rec := httptest.NewRecorder()
	s.handleOAuthCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/login?error=invalid_state") {
		t.Fatalf("expected invalid_state redirect, got %s", loc)
	}
}
