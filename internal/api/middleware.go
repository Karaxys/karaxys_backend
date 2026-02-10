package api
import(
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"golang.org/x/time/rate"
)

type Middleware struct {
	mu          sync.Mutex
	clients     map[string]*clientLimiter
	rps         float64
	burst       int
	lastCleanup time.Time
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewMiddleware(rps float64, burst int) *Middleware {
	return &Middleware{
		clients:     make(map[string]*clientLimiter),
		rps:         rps,
		burst:       burst,
		lastCleanup: time.Now(),
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
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		limiter := m.getLimiter(clientID(r))
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
			if !isAllowedOrigin(origin) {
				http.Error(w, "Origin Not Allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
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

func isAllowedOrigin(origin string) bool {
	return origin == "http://localhost:7000"
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}