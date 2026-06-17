package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

const (
	defaultMongoURI            = "mongodb://localhost:27017"
	defaultMongoDBName         = "karaxys"
	defaultTrafficLogMaxEvents = 1000
	defaultTrafficLogTTLHours  = 24
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

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()
	config := &Config{}
	var missingVars []string

	config.MongoURI = getEnvDefault("MONGO_URI", defaultMongoURI)
	config.MongoDBName = getEnvDefault("MONGO_DB_NAME", defaultMongoDBName)
	config.ProxyAddr = getEnv("PROXY_ADDR", &missingVars)
	config.CertFile = getEnv("PROXY_CERT_FILE", &missingVars)
	config.KeyFile = getEnv("PROXY_KEY_FILE", &missingVars)
	config.TrafficLogMaxEvents = getInt64EnvDefault("TRAFFIC_LOG_MAX_EVENTS", defaultTrafficLogMaxEvents)
	config.TrafficLogTTL = time.Duration(getInt64EnvDefault("TRAFFIC_LOG_TTL_HOURS", defaultTrafficLogTTLHours)) * time.Hour

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
