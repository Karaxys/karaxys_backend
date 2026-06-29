package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"karaxys_backend/internal/config"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"

	"golang.org/x/oauth2"
)

const (
	oauthStateCookieName = "karaxys_oauth_state"
	oauthStateTTL        = 10 * time.Minute
)

// Provider OAuth endpoints defined inline to avoid pulling the heavy
// google/github oauth2 subpackages (which drag in cloud default-credential code).
var (
	googleOAuthEndpoint = oauth2.Endpoint{
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
	}
	githubOAuthEndpoint = oauth2.Endpoint{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	}
)

// providerOAuthConfig builds the oauth2 config for a provider from env, or
// returns ok=false when the provider is not configured.
func providerOAuthConfig(provider string) (*oauth2.Config, bool) {
	redirectBase := strings.TrimRight(strings.TrimSpace(os.Getenv("KARAXYS_OAUTH_REDIRECT_BASE_URL")), "/")
	if redirectBase == "" {
		redirectBase = "http://localhost:8081"
	}
	redirectURL := fmt.Sprintf("%s/auth/oauth/%s/callback", redirectBase, provider)

	switch provider {
	case core.OAuthProviderGoogle:
		id := strings.TrimSpace(os.Getenv("KARAXYS_OAUTH_GOOGLE_CLIENT_ID"))
		secret := strings.TrimSpace(os.Getenv("KARAXYS_OAUTH_GOOGLE_CLIENT_SECRET"))
		if id == "" || secret == "" {
			return nil, false
		}
		return &oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			RedirectURL:  redirectURL,
			Endpoint:     googleOAuthEndpoint,
			Scopes:       []string{"openid", "email", "profile"},
		}, true
	case core.OAuthProviderGitHub:
		id := strings.TrimSpace(os.Getenv("KARAXYS_OAUTH_GITHUB_CLIENT_ID"))
		secret := strings.TrimSpace(os.Getenv("KARAXYS_OAUTH_GITHUB_CLIENT_SECRET"))
		if id == "" || secret == "" {
			return nil, false
		}
		return &oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			RedirectURL:  redirectURL,
			Endpoint:     githubOAuthEndpoint,
			Scopes:       []string{"read:user", "user:email"},
		}, true
	default:
		return nil, false
	}
}

func isSupportedOAuthProvider(provider string) bool {
	return provider == core.OAuthProviderGoogle || provider == core.OAuthProviderGitHub
}

func dashboardURL() string {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("KARAXYS_DASHBOARD_URL")), "/")
	if base == "" {
		base = "http://localhost:7000"
	}
	return base
}

func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !isSupportedOAuthProvider(provider) {
		http.Error(w, "Unsupported provider", http.StatusNotFound)
		return
	}
	cfg, ok := providerOAuthConfig(provider)
	if !ok {
		http.Error(w, "OAuth provider not configured", http.StatusServiceUnavailable)
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "Failed to start OAuth", http.StatusInternalServerError)
		return
	}
	setOAuthStateCookie(w, provider+":"+state)
	http.Redirect(w, r, cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !isSupportedOAuthProvider(provider) {
		http.Error(w, "Unsupported provider", http.StatusNotFound)
		return
	}

	// Provider-reported error (e.g. user denied consent).
	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		s.redirectOAuthError(w, r, "access_denied")
		return
	}

	cfg, ok := providerOAuthConfig(provider)
	if !ok {
		http.Error(w, "OAuth provider not configured", http.StatusServiceUnavailable)
		return
	}

	// CSRF: state in the query must match the signed value in the cookie.
	cookieState := oauthStateFromRequest(r)
	clearOAuthStateCookie(w)
	queryState := r.URL.Query().Get("state")
	if cookieState == "" || queryState == "" || cookieState != provider+":"+queryState {
		s.redirectOAuthError(w, r, "invalid_state")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.redirectOAuthError(w, r, "missing_code")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		s.redirectOAuthError(w, r, "exchange_failed")
		return
	}

	profile, err := fetchOAuthProfile(ctx, provider, cfg, token)
	if err != nil {
		s.redirectOAuthError(w, r, "profile_failed")
		return
	}

	account, user, err := s.DB.ResolveOAuthLogin(profile)
	if err != nil {
		reason := "login_failed"
		if errors.Is(err, db.ErrOAuthEmailUnverified) {
			reason = "email_unverified"
		} else if errors.Is(err, db.ErrDuplicateUser) {
			reason = "account_exists"
		}
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, "", "", "oauth "+provider+" "+reason)
		s.redirectOAuthError(w, r, reason)
		return
	}

	if _, err := s.createSessionResponse(w, r, user, account); err != nil {
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, user.ID.Hex(), account.ID.Hex(), "oauth session creation failed")
		s.redirectOAuthError(w, r, "session_failed")
		return
	}
	_ = s.DB.MarkUserLogin(user.ID)
	s.auditAuth(r, core.AuditActionLogin, core.AuditStatusSuccess, user.ID.Hex(), account.ID.Hex(), "oauth "+provider)
	// Pre-create the ingest token for new OAuth accounts (idempotent for existing ones).
	go s.ensureAccountIngestToken(account.ID)
	http.Redirect(w, r, dashboardURL()+"/auth/callback", http.StatusFound)
}

func (s *Server) redirectOAuthError(w http.ResponseWriter, r *http.Request, reason string) {
	target := dashboardURL() + "/login?error=" + url.QueryEscape(reason)
	http.Redirect(w, r, target, http.StatusFound)
}

func fetchOAuthProfile(ctx context.Context, provider string, cfg *oauth2.Config, token *oauth2.Token) (db.OAuthProfile, error) {
	client := cfg.Client(ctx, token)
	switch provider {
	case core.OAuthProviderGoogle:
		var data struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := getJSON(ctx, client, "https://openidconnect.googleapis.com/v1/userinfo", &data); err != nil {
			return db.OAuthProfile{}, err
		}
		if data.Sub == "" {
			return db.OAuthProfile{}, errors.New("google profile missing subject")
		}
		return db.OAuthProfile{
			Provider:       provider,
			ProviderUserID: data.Sub,
			Email:          data.Email,
			EmailVerified:  data.EmailVerified,
			Name:           data.Name,
		}, nil
	case core.OAuthProviderGitHub:
		var profile struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := getJSON(ctx, client, "https://api.github.com/user", &profile); err != nil {
			return db.OAuthProfile{}, err
		}
		if profile.ID == 0 {
			return db.OAuthProfile{}, errors.New("github profile missing id")
		}
		email := profile.Email
		verified := false
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := getJSON(ctx, client, "https://api.github.com/user/emails", &emails); err == nil {
			for _, e := range emails {
				if e.Primary {
					email = e.Email
					verified = e.Verified
					break
				}
			}
		}
		name := profile.Name
		if name == "" {
			name = profile.Login
		}
		return db.OAuthProfile{
			Provider:       provider,
			ProviderUserID: strconv.FormatInt(profile.ID, 10),
			Email:          email,
			EmailVerified:  verified,
			Name:           name,
		}, nil
	default:
		return db.OAuthProfile{}, errors.New("unsupported provider")
	}
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, target interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setOAuthStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(oauthStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   config.IsProduction(),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   config.IsProduction(),
		SameSite: http.SameSiteLaxMode,
	})
}

func oauthStateFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(oauthStateCookieName); err == nil {
		return cookie.Value
	}
	return ""
}
