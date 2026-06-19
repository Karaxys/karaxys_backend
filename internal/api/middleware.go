package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const DefaultMaxWriteBodyBytes int64 = 1 * 1024 * 1024

type contextKey string

const subjectContextKey contextKey = "karaxys_subject"
const principalContextKey contextKey = "karaxys_principal"

type Principal struct {
	Subject   string
	ActorType string
	UserID    string
	AccountID string
	Role      string
}

type SessionAuthenticator func(token string) (*Principal, bool)

type Middleware struct {
	mu                sync.Mutex
	clients           map[string]*clientLimiter
	rps               float64
	burst             int
	lastCleanup       time.Time
	apiKey            string
	apiKeyAccountID   string
	apiKeyRole        string
	sessionAuth       SessionAuthenticator
	allowedOrigins    map[string]struct{}
	maxWriteBodyBytes int64
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type MiddlewareOptions struct {
	APIKey            string
	APIKeyAccountID   string
	APIKeyRole        string
	SessionAuth       SessionAuthenticator
	AllowedOrigins    []string
	MaxWriteBodyBytes int64
}

func NewMiddleware(rps float64, burst int, options ...MiddlewareOptions) *Middleware {
	opts := MiddlewareOptions{
		AllowedOrigins:    []string{"http://localhost:7000"},
		MaxWriteBodyBytes: DefaultMaxWriteBodyBytes,
	}
	if len(options) > 0 {
		opts = options[0]
		if len(opts.AllowedOrigins) == 0 {
			opts.AllowedOrigins = []string{"http://localhost:7000"}
		}
		if opts.MaxWriteBodyBytes <= 0 {
			opts.MaxWriteBodyBytes = DefaultMaxWriteBodyBytes
		}
	}

	return &Middleware{
		clients:           make(map[string]*clientLimiter),
		rps:               rps,
		burst:             burst,
		lastCleanup:       time.Now(),
		apiKey:            strings.TrimSpace(opts.APIKey),
		apiKeyAccountID:   strings.TrimSpace(opts.APIKeyAccountID),
		apiKeyRole:        normalizeAPIKeyRole(opts.APIKeyRole),
		sessionAuth:       opts.SessionAuth,
		allowedOrigins:    originSet(opts.AllowedOrigins),
		maxWriteBodyBytes: opts.MaxWriteBodyBytes,
	}
}

func (m *Middleware) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("[%s] %s | Status: %d | Duration: %v", r.Method, r.URL.Path, rw.statusCode, time.Since(start))
	})
}

func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || isExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			token = r.Header.Get("X-API-Key")
		}
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if m.sessionAuth != nil {
			if principal, ok := m.sessionAuth(token); ok && principal != nil {
				if principal.Subject == "" {
					principal.Subject = "user:" + principal.UserID
				}
				ctx := context.WithValue(r.Context(), subjectContextKey, principal.Subject)
				ctx = context.WithValue(ctx, principalContextKey, *principal)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		if m.apiKey == "" {
			http.Error(w, "API authentication is not configured", http.StatusServiceUnavailable)
			return
		}
		if token == "" || !constantTimeEqual(token, m.apiKey) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		principal := Principal{
			Subject:   subjectFromToken(token),
			ActorType: "api_key",
			AccountID: m.apiKeyAccountID,
			Role:      m.apiKeyRole,
		}
		ctx := context.WithValue(r.Context(), subjectContextKey, principal.Subject)
		ctx = context.WithValue(ctx, principalContextKey, principal)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		limiter := m.getLimiter(m.rateLimitKey(r))
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests - Slow Down", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("RECOVERED: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !m.isAllowedOrigin(origin) {
				http.Error(w, "Origin Not Allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) LimitWriteBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWriteMethod(r.Method) && !isIngestionPath(r.URL.Path) && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, m.maxWriteBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) getLimiter(key string) *rate.Limiter {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	if now.Sub(m.lastCleanup) > time.Minute {
		for k, v := range m.clients {
			if now.Sub(v.lastSeen) > 5*time.Minute {
				delete(m.clients, k)
			}
		}
		m.lastCleanup = now
	}

	if client, ok := m.clients[key]; ok {
		client.lastSeen = now
		return client.limiter
	}

	limiter := rate.NewLimiter(rate.Limit(m.rps), m.burst)
	m.clients[key] = &clientLimiter{limiter: limiter, lastSeen: now}
	return limiter
}

func clientID(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (m *Middleware) rateLimitKey(r *http.Request) string {
	if subject, ok := r.Context().Value(subjectContextKey).(string); ok && subject != "" {
		return subject
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = r.Header.Get("X-API-Key")
	}
	if m.apiKey != "" && token != "" && constantTimeEqual(token, m.apiKey) {
		return subjectFromToken(token)
	}
	return "ip:" + clientID(r)
}

func (m *Middleware) isAllowedOrigin(origin string) bool {
	_, ok := m.allowedOrigins[origin]
	return ok
}

func originSet(origins []string) map[string]struct{} {
	set := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			set[origin] = struct{}{}
		}
	}
	return set
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func constantTimeEqual(actual string, expected string) bool {
	actualHash := sha256.Sum256([]byte(actual))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(actualHash[:], expectedHash[:]) == 1
}

func subjectFromToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return "api_key:" + hex.EncodeToString(hash[:8])
}

func SubjectFromContext(ctx context.Context) string {
	if subject, ok := ctx.Value(subjectContextKey).(string); ok {
		return subject
	}
	return ""
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if principal, ok := ctx.Value(principalContextKey).(Principal); ok {
		return principal, true
	}
	return Principal{}, false
}

func isExemptPath(path string) bool {
	if isIngestionPath(path) {
		return true
	}
	switch path {
	case "/auth/signup", "/auth/login", "/auth/refresh", "/agents/register":
		return true
	default:
		return false
	}
}

func isIngestionPath(path string) bool {
	return path == "/v1/ingest/conversations"
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
