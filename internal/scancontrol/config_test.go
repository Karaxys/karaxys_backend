package scancontrol

import (
	"testing"
	"time"

	"karaxys_backend/internal/core"
)

func TestLoadConfigFromEnvDefaultsDisableTargetJobRateOutsideProduction(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "development")
	t.Setenv("KARAXYS_SCANNER_TARGET_JOBS_PER_WINDOW", "")

	cfg := LoadConfigFromEnv().Normalize()
	if cfg.TargetJobsPerWindow != 0 {
		t.Fatalf("expected local target job rate limiting to be disabled by default, got %d", cfg.TargetJobsPerWindow)
	}
	if cfg.GlobalConcurrency != defaultGlobalConcurrency {
		t.Fatalf("unexpected global concurrency: %d", cfg.GlobalConcurrency)
	}
}

func TestLoadConfigFromEnvDefaultsEnableTargetJobRateInProduction(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "production")
	t.Setenv("KARAXYS_SCANNER_TARGET_JOBS_PER_WINDOW", "")

	cfg := LoadConfigFromEnv().Normalize()
	if cfg.TargetJobsPerWindow != defaultTargetJobsPerWindow {
		t.Fatalf("unexpected production target job limit: %d", cfg.TargetJobsPerWindow)
	}
}

func TestLoadConfigFromEnvHonorsOverrides(t *testing.T) {
	t.Setenv("KARAXYS_SCANNER_GLOBAL_CONCURRENCY", "7")
	t.Setenv("KARAXYS_SCANNER_TARGET_JOBS_PER_WINDOW", "3")
	t.Setenv("KARAXYS_SCANNER_TARGET_RATE_WINDOW_SECONDS", "45")
	t.Setenv("KARAXYS_SCANNER_CAPACITY_RETRY_SECONDS", "9")
	t.Setenv("KARAXYS_NUCLEI_RATE_LIMIT_PER_SECOND", "11")

	cfg := LoadConfigFromEnv().Normalize()
	if cfg.GlobalConcurrency != 7 {
		t.Fatalf("unexpected global concurrency: %d", cfg.GlobalConcurrency)
	}
	if cfg.TargetJobsPerWindow != 3 {
		t.Fatalf("unexpected target job limit: %d", cfg.TargetJobsPerWindow)
	}
	if cfg.TargetRateWindow != 45*time.Second {
		t.Fatalf("unexpected target rate window: %s", cfg.TargetRateWindow)
	}
	if cfg.CapacityRetryDelay != 9*time.Second {
		t.Fatalf("unexpected retry delay: %s", cfg.CapacityRetryDelay)
	}
	if cfg.NucleiRateLimitPerSecond != 11 {
		t.Fatalf("unexpected nuclei rate limit: %d", cfg.NucleiRateLimitPerSecond)
	}
}

func TestApplyExecutionLimitsPersistsScannerKnobs(t *testing.T) {
	scanConfig := ApplyExecutionLimits(core.ScanConfig{TargetURL: "https://api.example.com"}, Config{
		NucleiRateLimitPerSecond:  13,
		NucleiTemplateConcurrency: 2,
		NucleiHostConcurrency:     3,
		NucleiPayloadConcurrency:  4,
		NucleiProbeConcurrency:    5,
	})

	if scanConfig.RateLimitPerSecond != 13 ||
		scanConfig.TemplateConcurrency != 2 ||
		scanConfig.HostConcurrency != 3 ||
		scanConfig.PayloadConcurrency != 4 ||
		scanConfig.ProbeConcurrency != 5 {
		t.Fatalf("execution limits were not applied: %+v", scanConfig)
	}
}

func TestTargetRateKeyIsTenantAndHostScoped(t *testing.T) {
	job := core.ScanJob{
		TenantID: "tenant-1",
		Config: core.ScanConfig{
			TargetURL: "HTTPS://Api.Example.com:8443/path?token=secret",
		},
	}

	key, err := TargetRateKey(job)
	if err != nil {
		t.Fatalf("target rate key: %v", err)
	}
	expected := "tenant:tenant-1|target:https://api.example.com:8443"
	if key != expected {
		t.Fatalf("unexpected key: %s", key)
	}
}

func TestTargetRateKeyAddsDefaultPort(t *testing.T) {
	job := core.ScanJob{
		TenantID: "tenant-1",
		Config: core.ScanConfig{
			TargetURL: "http://api.example.com/v1",
		},
	}

	key, err := TargetRateKey(job)
	if err != nil {
		t.Fatalf("target rate key: %v", err)
	}
	expected := "tenant:tenant-1|target:http://api.example.com:80"
	if key != expected {
		t.Fatalf("unexpected key: %s", key)
	}
}

func TestTargetRateKeyRejectsInvalidTargets(t *testing.T) {
	_, err := TargetRateKey(core.ScanJob{Config: core.ScanConfig{TargetURL: "not a url"}})
	if err == nil {
		t.Fatal("expected invalid target to fail")
	}
}
