package coordination

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultRedisKeyPrefix  = "karaxys"
	defaultScanProgressTTL = 2 * time.Hour
)

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

type DistributedLock interface {
	Release(ctx context.Context) error
}

type Locker interface {
	TryLock(ctx context.Context, key string, value string, ttl time.Duration) (DistributedLock, bool, error)
}

type Semaphore interface {
	TryAcquire(ctx context.Context, key string, value string, limit int, ttl time.Duration) (DistributedLock, bool, error)
}

type ScanProgressCache interface {
	Set(ctx context.Context, progress ScanProgress, ttl time.Duration) error
	Delete(ctx context.Context, jobID string) error
}

type ScanProgress struct {
	JobID        string    `json:"job_id"`
	Status       string    `json:"status"`
	WorkerID     string    `json:"worker_id,omitempty"`
	Message      string    `json:"message,omitempty"`
	ResultsCount int       `json:"results_count,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type RedisConfig struct {
	Addr      string
	Username  string
	Password  string
	DB        int
	UseTLS    bool
	KeyPrefix string
}

type RedisRuntime struct {
	Client      *redis.Client
	RateLimiter RateLimiter
	Locker      Locker
	Semaphore   Semaphore
	Progress    ScanProgressCache
	KeyPrefix   string
	ProgressTTL time.Duration
	ScanLockTTL time.Duration
}

func NewRedisRuntimeFromEnv() (*RedisRuntime, error) {
	cfg := RedisConfig{
		Addr:      strings.TrimSpace(os.Getenv("KARAXYS_REDIS_ADDR")),
		Username:  strings.TrimSpace(os.Getenv("KARAXYS_REDIS_USERNAME")),
		Password:  os.Getenv("KARAXYS_REDIS_PASSWORD"),
		DB:        intEnvDefault("KARAXYS_REDIS_DB", 0),
		UseTLS:    boolEnvDefault("KARAXYS_REDIS_TLS", false),
		KeyPrefix: strings.TrimSpace(os.Getenv("KARAXYS_REDIS_KEY_PREFIX")),
	}
	if cfg.Addr == "" {
		return nil, nil
	}
	client, prefix, err := NewRedisClient(cfg)
	if err != nil {
		return nil, err
	}
	progressTTL := durationEnvDefault("KARAXYS_SCAN_PROGRESS_TTL_SECONDS", defaultScanProgressTTL)
	scanLockTTL := durationEnvDefault("KARAXYS_SCAN_LOCK_TTL_SECONDS", 30*time.Minute)
	return &RedisRuntime{
		Client:      client,
		RateLimiter: NewRedisRateLimiter(client, prefix),
		Locker:      NewRedisLocker(client, prefix),
		Semaphore:   NewRedisSemaphore(client, prefix),
		Progress:    NewRedisScanProgressCache(client, prefix),
		KeyPrefix:   prefix,
		ProgressTTL: progressTTL,
		ScanLockTTL: scanLockTTL,
	}, nil
}

func NewRedisClient(cfg RedisConfig) (*redis.Client, string, error) {
	cfg.Addr = strings.TrimSpace(cfg.Addr)
	if cfg.Addr == "" {
		return nil, "", fmt.Errorf("redis address is required")
	}
	prefix := strings.TrimSpace(cfg.KeyPrefix)
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.UseTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	return client, prefix, nil
}

func (r *RedisRuntime) Close() error {
	if r == nil || r.Client == nil {
		return nil
	}
	return r.Client.Close()
}

type RedisRateLimiter struct {
	client *redis.Client
	prefix string
}

func NewRedisRateLimiter(client *redis.Client, prefix string) *RedisRateLimiter {
	return &RedisRateLimiter{client: client, prefix: normalizedPrefix(prefix)}
}

func (r *RedisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if r == nil || r.client == nil {
		return true, nil
	}
	if limit <= 0 {
		return false, nil
	}
	if window <= 0 {
		window = time.Second
	}
	count, err := redisRateLimitScript.Run(ctx, r.client, []string{hashedKey(r.prefix, "rate_limit", key)}, limit, window.Milliseconds()).Int()
	if err != nil {
		return false, err
	}
	return count <= limit, nil
}

var redisRateLimitScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return current
`)

type RedisLocker struct {
	client *redis.Client
	prefix string
}

func NewRedisLocker(client *redis.Client, prefix string) *RedisLocker {
	return &RedisLocker{client: client, prefix: normalizedPrefix(prefix)}
}

func (l *RedisLocker) TryLock(ctx context.Context, key string, value string, ttl time.Duration) (DistributedLock, bool, error) {
	if l == nil || l.client == nil {
		return noopLock{}, true, nil
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
		return nil, false, fmt.Errorf("lock key and value are required")
	}
	if ttl <= 0 {
		return nil, false, fmt.Errorf("lock ttl must be positive")
	}
	redisKey := plainKey(l.prefix, "lock", key)
	ok, err := l.client.SetNX(ctx, redisKey, value, ttl).Result()
	if err != nil || !ok {
		return nil, ok, err
	}
	return &redisLock{client: l.client, key: redisKey, value: value}, true, nil
}

type redisLock struct {
	client *redis.Client
	key    string
	value  string
}

func (l *redisLock) Release(ctx context.Context) error {
	if l == nil || l.client == nil {
		return nil
	}
	_, err := redisReleaseLockScript.Run(ctx, l.client, []string{l.key}, l.value).Int()
	return err
}

var redisReleaseLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
`)

type noopLock struct{}

func (noopLock) Release(context.Context) error { return nil }

type RedisSemaphore struct {
	client *redis.Client
	prefix string
}

func NewRedisSemaphore(client *redis.Client, prefix string) *RedisSemaphore {
	return &RedisSemaphore{client: client, prefix: normalizedPrefix(prefix)}
}

func (s *RedisSemaphore) TryAcquire(ctx context.Context, key string, value string, limit int, ttl time.Duration) (DistributedLock, bool, error) {
	if s == nil || s.client == nil {
		return noopLock{}, true, nil
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return nil, false, fmt.Errorf("semaphore key and value are required")
	}
	if limit <= 0 {
		return nil, false, fmt.Errorf("semaphore limit must be positive")
	}
	if ttl <= 0 {
		return nil, false, fmt.Errorf("semaphore ttl must be positive")
	}
	for slot := 0; slot < limit; slot++ {
		redisKey := plainKey(s.prefix, "semaphore", key, strconv.Itoa(slot))
		ok, err := s.client.SetNX(ctx, redisKey, value, ttl).Result()
		if err != nil {
			return nil, false, err
		}
		if ok {
			return &redisLock{client: s.client, key: redisKey, value: value}, true, nil
		}
	}
	return nil, false, nil
}

type RedisScanProgressCache struct {
	client *redis.Client
	prefix string
}

func NewRedisScanProgressCache(client *redis.Client, prefix string) *RedisScanProgressCache {
	return &RedisScanProgressCache{client: client, prefix: normalizedPrefix(prefix)}
}

func (c *RedisScanProgressCache) Set(ctx context.Context, progress ScanProgress, ttl time.Duration) error {
	if c == nil || c.client == nil {
		return nil
	}
	progress.JobID = strings.TrimSpace(progress.JobID)
	if progress.JobID == "" {
		return fmt.Errorf("scan progress job id is required")
	}
	if ttl <= 0 {
		ttl = defaultScanProgressTTL
	}
	if progress.UpdatedAt.IsZero() {
		progress.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, ScanProgressKey(c.prefix, progress.JobID), raw, ttl).Err()
}

func (c *RedisScanProgressCache) Delete(ctx context.Context, jobID string) error {
	if c == nil || c.client == nil {
		return nil
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil
	}
	return c.client.Del(ctx, ScanProgressKey(c.prefix, jobID)).Err()
}

func ScanJobLockKey(jobID string) string {
	return "scan_job:" + strings.TrimSpace(jobID)
}

func ScannerGlobalSemaphoreKey() string {
	return "scanner:global"
}

func ScanProgressKey(prefix string, jobID string) string {
	return plainKey(prefix, "scan_progress", strings.TrimSpace(jobID))
}

func hashedKey(prefix string, namespace string, key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return plainKey(prefix, namespace, hex.EncodeToString(sum[:]))
}

func plainKey(prefix string, parts ...string) string {
	prefix = normalizedPrefix(prefix)
	out := []string{prefix}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, strings.ReplaceAll(part, ":", "_"))
	}
	return strings.Join(out, ":")
}

func normalizedPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return defaultRedisKeyPrefix
	}
	return strings.ReplaceAll(prefix, ":", "_")
}

func intEnvDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func boolEnvDefault(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func durationEnvDefault(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Second
}
