package scancontrol

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"karaxys_backend/internal/config"
	"karaxys_backend/internal/core"
)

const (
	defaultGlobalConcurrency         = 2
	defaultTargetJobsPerWindow       = 1
	defaultTargetRateWindowSeconds   = 30
	defaultCapacityRetrySeconds      = 5
	defaultAdmissionLeaseSeconds     = 1800
	defaultNucleiRateLimitPerSecond  = 5
	defaultNucleiTemplateConcurrency = 1
	defaultNucleiHostConcurrency     = 1
	defaultNucleiPayloadConcurrency  = 2
	defaultNucleiProbeConcurrency    = 5
)

type Config struct {
	GlobalConcurrency         int
	TargetJobsPerWindow       int
	TargetRateWindow          time.Duration
	CapacityRetryDelay        time.Duration
	AdmissionLease            time.Duration
	NucleiRateLimitPerSecond  int
	NucleiTemplateConcurrency int
	NucleiHostConcurrency     int
	NucleiPayloadConcurrency  int
	NucleiProbeConcurrency    int
}

func LoadConfigFromEnv() Config {
	targetJobsDefault := defaultTargetJobsPerWindow
	if !config.IsProduction() && strings.TrimSpace(os.Getenv("KARAXYS_SCANNER_TARGET_JOBS_PER_WINDOW")) == "" {
		targetJobsDefault = 0
	}
	return Config{
		GlobalConcurrency:         intEnvDefault("KARAXYS_SCANNER_GLOBAL_CONCURRENCY", defaultGlobalConcurrency),
		TargetJobsPerWindow:       intEnvDefault("KARAXYS_SCANNER_TARGET_JOBS_PER_WINDOW", targetJobsDefault),
		TargetRateWindow:          durationEnvDefault("KARAXYS_SCANNER_TARGET_RATE_WINDOW_SECONDS", defaultTargetRateWindowSeconds),
		CapacityRetryDelay:        durationEnvDefault("KARAXYS_SCANNER_CAPACITY_RETRY_SECONDS", defaultCapacityRetrySeconds),
		AdmissionLease:            durationEnvDefault("KARAXYS_SCANNER_ADMISSION_LEASE_SECONDS", defaultAdmissionLeaseSeconds),
		NucleiRateLimitPerSecond:  intEnvDefault("KARAXYS_NUCLEI_RATE_LIMIT_PER_SECOND", defaultNucleiRateLimitPerSecond),
		NucleiTemplateConcurrency: intEnvDefault("KARAXYS_NUCLEI_TEMPLATE_CONCURRENCY", defaultNucleiTemplateConcurrency),
		NucleiHostConcurrency:     intEnvDefault("KARAXYS_NUCLEI_HOST_CONCURRENCY", defaultNucleiHostConcurrency),
		NucleiPayloadConcurrency:  intEnvDefault("KARAXYS_NUCLEI_PAYLOAD_CONCURRENCY", defaultNucleiPayloadConcurrency),
		NucleiProbeConcurrency:    intEnvDefault("KARAXYS_NUCLEI_PROBE_CONCURRENCY", defaultNucleiProbeConcurrency),
	}
}

func (c Config) Normalize() Config {
	if c.GlobalConcurrency <= 0 {
		c.GlobalConcurrency = defaultGlobalConcurrency
	}
	if c.TargetJobsPerWindow < 0 {
		c.TargetJobsPerWindow = defaultTargetJobsPerWindow
	}
	if c.TargetRateWindow <= 0 {
		c.TargetRateWindow = time.Duration(defaultTargetRateWindowSeconds) * time.Second
	}
	if c.CapacityRetryDelay <= 0 {
		c.CapacityRetryDelay = time.Duration(defaultCapacityRetrySeconds) * time.Second
	}
	if c.AdmissionLease <= 0 {
		c.AdmissionLease = time.Duration(defaultAdmissionLeaseSeconds) * time.Second
	}
	if c.NucleiRateLimitPerSecond < 0 {
		c.NucleiRateLimitPerSecond = defaultNucleiRateLimitPerSecond
	}
	if c.NucleiTemplateConcurrency <= 0 {
		c.NucleiTemplateConcurrency = defaultNucleiTemplateConcurrency
	}
	if c.NucleiHostConcurrency <= 0 {
		c.NucleiHostConcurrency = defaultNucleiHostConcurrency
	}
	if c.NucleiPayloadConcurrency <= 0 {
		c.NucleiPayloadConcurrency = defaultNucleiPayloadConcurrency
	}
	if c.NucleiProbeConcurrency <= 0 {
		c.NucleiProbeConcurrency = defaultNucleiProbeConcurrency
	}
	return c
}

func ApplyExecutionLimits(scanConfig core.ScanConfig, limits Config) core.ScanConfig {
	limits = limits.Normalize()
	scanConfig.RateLimitPerSecond = limits.NucleiRateLimitPerSecond
	scanConfig.TemplateConcurrency = limits.NucleiTemplateConcurrency
	scanConfig.HostConcurrency = limits.NucleiHostConcurrency
	scanConfig.PayloadConcurrency = limits.NucleiPayloadConcurrency
	scanConfig.ProbeConcurrency = limits.NucleiProbeConcurrency
	return scanConfig
}

func TargetRateKey(job core.ScanJob) (string, error) {
	target := strings.TrimSpace(job.Config.TargetURL)
	if target == "" {
		return "", fmt.Errorf("scan target URL is required")
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid scan target URL")
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = ""
		}
	}
	hostPort := host
	if port != "" {
		hostPort = net.JoinHostPort(host, port)
	}
	tenant := strings.TrimSpace(job.TenantID)
	if tenant == "" {
		tenant = "unscoped"
	}
	return "tenant:" + tenant + "|target:" + strings.ToLower(parsed.Scheme) + "://" + hostPort, nil
}

func intEnvDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func durationEnvDefault(key string, fallbackSeconds int) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return time.Duration(fallbackSeconds) * time.Second
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return time.Duration(fallbackSeconds) * time.Second
	}
	return time.Duration(value) * time.Second
}
