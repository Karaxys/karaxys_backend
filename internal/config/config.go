package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

const (
	defaultMongoURI            = "mongodb://127.0.0.1:27017/?directConnection=true"
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

type DatabaseConfig struct {
	MongoURI            string
	MongoDBName         string
	TrafficLogMaxEvents int64
	TrafficLogTTL       time.Duration
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
