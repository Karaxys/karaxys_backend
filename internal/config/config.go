package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	defaultMongoURI            = "mongodb://127.0.0.1:27017/?directConnection=true"
	defaultMongoDBName         = "karaxys"
	defaultTrafficLogMaxEvents = 1000
	defaultTrafficLogTTLHours  = 24
)

const (
	ServiceAPIServer     = "api-server"
	ServiceScannerWorker = "scanner-worker"
	ServiceLegacyProxy   = "legacy-proxy"
)

type Config struct {
	MongoURI            string
	MongoDBName         string
	ProxyAddr           string
	CertFile            string
	KeyFile             string
	TrafficLogMaxEvents int64
	TrafficLogTTL       time.Duration
}

type DatabaseConfig struct {
	MongoURI            string
	MongoDBName         string
	TrafficLogMaxEvents int64
	TrafficLogTTL       time.Duration
}

func IsProduction() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("KARAXYS_ENV")), "production")
}

func ValidateProductionEnvironment(service string) error {
	if !IsProduction() {
		return nil
	}

	var required []string
	switch service {
	case ServiceAPIServer:
		required = []string{"MONGO_URI", "MONGO_DB_NAME", "KARAXYS_ALLOWED_ORIGINS", "KARAXYS_SECRET_KEY_B64"}
	case ServiceScannerWorker:
		required = []string{"MONGO_URI", "MONGO_DB_NAME", "KARAXYS_SECRET_KEY_B64"}
	case ServiceLegacyProxy:
		required = []string{"MONGO_URI", "MONGO_DB_NAME", "KARAXYS_API_KEY", "KARAXYS_AGENT_TOKEN", "KARAXYS_ALLOWED_ORIGINS", "KARAXYS_SECRET_KEY_B64", "PROXY_ADDR", "PROXY_CERT_FILE", "PROXY_KEY_FILE"}
	default:
		required = []string{"MONGO_URI", "MONGO_DB_NAME"}
	}

	var problems []string
	for _, key := range required {
		if invalidProductionValue(os.Getenv(key)) {
			problems = append(problems, key)
		}
	}
	if key := os.Getenv("KARAXYS_API_KEY"); key != "" && len(key) < 24 {
		problems = append(problems, "KARAXYS_API_KEY must be at least 24 characters")
	}
	if token := os.Getenv("KARAXYS_AGENT_TOKEN"); token != "" && len(token) < 24 {
		problems = append(problems, "KARAXYS_AGENT_TOKEN must be at least 24 characters")
	}
	if origins := os.Getenv("KARAXYS_ALLOWED_ORIGINS"); origins != "" {
		if strings.Contains(origins, "*") || strings.Contains(origins, "localhost") || strings.Contains(origins, "127.0.0.1") {
			problems = append(problems, "KARAXYS_ALLOWED_ORIGINS must not use wildcard or localhost values in production")
		}
	}
	if secretKey := os.Getenv("KARAXYS_SECRET_KEY_B64"); secretKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(secretKey)
		if err != nil || len(decoded) != 32 {
			problems = append(problems, "KARAXYS_SECRET_KEY_B64 must decode to exactly 32 bytes")
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid production environment for %s: %s", service, strings.Join(problems, ", "))
	}
	return nil
}

func invalidProductionValue(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.Contains(strings.ToLower(value), "replace-with")
}

func LoadDatabaseConfig() (*DatabaseConfig, error) {
	_ = godotenv.Load()
	return &DatabaseConfig{
		MongoURI:            getEnvDefault("MONGO_URI", defaultMongoURI),
		MongoDBName:         getEnvDefault("MONGO_DB_NAME", defaultMongoDBName),
		TrafficLogMaxEvents: getInt64EnvDefault("TRAFFIC_LOG_MAX_EVENTS", defaultTrafficLogMaxEvents),
		TrafficLogTTL:       time.Duration(getInt64EnvDefault("TRAFFIC_LOG_TTL_HOURS", defaultTrafficLogTTLHours)) * time.Hour,
	}, nil
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()
	dbConfig, err := LoadDatabaseConfig()
	if err != nil {
		return nil, err
	}
	config := &Config{}
	var missingVars []string

	config.MongoURI = dbConfig.MongoURI
	config.MongoDBName = dbConfig.MongoDBName
	config.ProxyAddr = getEnv("PROXY_ADDR", &missingVars)
	config.CertFile = getEnv("PROXY_CERT_FILE", &missingVars)
	config.KeyFile = getEnv("PROXY_KEY_FILE", &missingVars)
	config.TrafficLogMaxEvents = dbConfig.TrafficLogMaxEvents
	config.TrafficLogTTL = dbConfig.TrafficLogTTL

	if len(missingVars) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missingVars)
	}
	return config, nil
}

func getEnv(key string, missingList *[]string) string {
	value := os.Getenv(key)
	if value == "" {
		*missingList = append(*missingList, key)
	}
	return value
}

func getEnvDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getInt64EnvDefault(key string, fallback int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
