package coordination

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRedisKeysAreScopedAndSanitized(t *testing.T) {
	if got := ScanJobLockKey("  job-1  "); got != "scan_job:job-1" {
		t.Fatalf("unexpected lock key: %s", got)
	}
	if got := ScanProgressKey("karaxys:test", "job:1"); got != "karaxys_test:scan_progress:job_1" {
		t.Fatalf("unexpected progress key: %s", got)
	}
	if got := ScannerGlobalSemaphoreKey(); got != "scanner:global" {
		t.Fatalf("unexpected scanner semaphore key: %s", got)
	}
	key := hashedKey("karaxys", "rate_limit", "subject:user-1")
	if !strings.HasPrefix(key, "karaxys:rate_limit:") {
		t.Fatalf("unexpected hashed key prefix: %s", key)
	}
	if strings.Contains(key, "subject:user-1") {
		t.Fatalf("hashed key leaked raw subject: %s", key)
	}
}

func TestNoopRedisImplementationsAllowLocalDevelopment(t *testing.T) {
	limiter := NewRedisRateLimiter(nil, "karaxys")
	allowed, err := limiter.Allow(context.Background(), "subject", 1, time.Second)
	if err != nil || !allowed {
		t.Fatalf("nil redis rate limiter should allow local development, allowed=%v err=%v", allowed, err)
	}

	locker := NewRedisLocker(nil, "karaxys")
	lock, acquired, err := locker.TryLock(context.Background(), "job", "worker", time.Second)
	if err != nil || !acquired {
		t.Fatalf("nil redis locker should acquire noop lock, acquired=%v err=%v", acquired, err)
	}
	if err := lock.Release(context.Background()); err != nil {
		t.Fatalf("noop release: %v", err)
	}

	semaphore := NewRedisSemaphore(nil, "karaxys")
	semLock, acquired, err := semaphore.TryAcquire(context.Background(), "scanner", "worker", 1, time.Second)
	if err != nil || !acquired {
		t.Fatalf("nil redis semaphore should acquire noop lock, acquired=%v err=%v", acquired, err)
	}
	if err := semLock.Release(context.Background()); err != nil {
		t.Fatalf("noop semaphore release: %v", err)
	}

	progress := NewRedisScanProgressCache(nil, "karaxys")
	if err := progress.Set(context.Background(), ScanProgress{JobID: "job-1", Status: "running"}, time.Minute); err != nil {
		t.Fatalf("nil redis progress set should be no-op: %v", err)
	}
}
