package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigDefaultsMongoAndRetention(t *testing.T) {
	t.Setenv("MONGO_URI", "")
	t.Setenv("MONGO_DB_NAME", "")
	t.Setenv("PROXY_ADDR", "127.0.0.1:8080")
	t.Setenv("PROXY_CERT_FILE", "cert.pem")
	t.Setenv("PROXY_KEY_FILE", "key.pem")
	t.Setenv("TRAFFIC_LOG_MAX_EVENTS", "")
	t.Setenv("TRAFFIC_LOG_TTL_HOURS", "")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.MongoURI != defaultMongoURI {
		t.Fatalf("unexpected MongoURI: %s", cfg.MongoURI)
	}
	if cfg.MongoDBName != defaultMongoDBName {
		t.Fatalf("unexpected MongoDBName: %s", cfg.MongoDBName)
	}
	if cfg.TrafficLogMaxEvents != defaultTrafficLogMaxEvents {
		t.Fatalf("unexpected max events: %d", cfg.TrafficLogMaxEvents)
	}
	if cfg.TrafficLogTTL != defaultTrafficLogTTLHours*time.Hour {
		t.Fatalf("unexpected TTL: %s", cfg.TrafficLogTTL)
	}
}

func TestLoadConfigParsesRetentionOverrides(t *testing.T) {
	t.Setenv("MONGO_URI", "mongodb://mongo:27017")
	t.Setenv("MONGO_DB_NAME", "karaxys_test")
	t.Setenv("PROXY_ADDR", "127.0.0.1:8080")
	t.Setenv("PROXY_CERT_FILE", "cert.pem")
	t.Setenv("PROXY_KEY_FILE", "key.pem")
	t.Setenv("TRAFFIC_LOG_MAX_EVENTS", "250")
	t.Setenv("TRAFFIC_LOG_TTL_HOURS", "6")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.TrafficLogMaxEvents != 250 {
		t.Fatalf("unexpected max events: %d", cfg.TrafficLogMaxEvents)
	}
	if cfg.TrafficLogTTL != 6*time.Hour {
		t.Fatalf("unexpected TTL: %s", cfg.TrafficLogTTL)
	}
}

func TestLoadDatabaseConfigDoesNotRequireProxySettings(t *testing.T) {
	t.Setenv("MONGO_URI", "")
	t.Setenv("MONGO_DB_NAME", "")
	t.Setenv("PROXY_ADDR", "")
	t.Setenv("PROXY_CERT_FILE", "")
	t.Setenv("PROXY_KEY_FILE", "")

	cfg, err := LoadDatabaseConfig()
	if err != nil {
		t.Fatalf("LoadDatabaseConfig returned error: %v", err)
	}
	if cfg.MongoURI != defaultMongoURI {
		t.Fatalf("unexpected MongoURI: %s", cfg.MongoURI)
	}
}

func TestValidateProductionEnvironmentNoopsOutsideProduction(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "development")
	t.Setenv("MONGO_URI", "")

	if err := ValidateProductionEnvironment(ServiceAPIServer); err != nil {
		t.Fatalf("expected no production validation error, got %v", err)
	}
}

func TestValidateProductionEnvironmentRejectsMissingValues(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "production")
	t.Setenv("MONGO_URI", "")
	t.Setenv("MONGO_DB_NAME", "")
	t.Setenv("KARAXYS_API_KEY", "")
	t.Setenv("KARAXYS_AGENT_TOKEN", "")
	t.Setenv("KARAXYS_ALLOWED_ORIGINS", "")
	t.Setenv("KARAXYS_SECRET_KEY_B64", "")

	err := ValidateProductionEnvironment(ServiceAPIServer)
	if err == nil {
		t.Fatalf("expected production validation error")
	}
	for _, expected := range []string{"MONGO_URI", "MONGO_DB_NAME", "KARAXYS_ALLOWED_ORIGINS", "KARAXYS_SECRET_KEY_B64"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("expected error to mention %s, got %v", expected, err)
		}
	}
}

func TestValidateProductionEnvironmentAcceptsCompleteAPIEnvironment(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "production")
	t.Setenv("MONGO_URI", "mongodb://mongo.internal:27017")
	t.Setenv("MONGO_DB_NAME", "karaxys")
	t.Setenv("KARAXYS_API_KEY", "api-key-with-at-least-24-characters")
	t.Setenv("KARAXYS_AGENT_TOKEN", "agent-token-with-at-least-24-chars")
	t.Setenv("KARAXYS_ALLOWED_ORIGINS", "https://karaxys.example.com")
	t.Setenv("KARAXYS_SECRET_KEY_B64", base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")))

	if err := ValidateProductionEnvironment(ServiceAPIServer); err != nil {
		t.Fatalf("unexpected production validation error: %v", err)
	}
}

func TestValidateProductionEnvironmentAcceptsSessionOnlyAPIEnvironment(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "production")
	t.Setenv("MONGO_URI", "mongodb://mongo.internal:27017")
	t.Setenv("MONGO_DB_NAME", "karaxys")
	t.Setenv("KARAXYS_API_KEY", "")
	t.Setenv("KARAXYS_AGENT_TOKEN", "")
	t.Setenv("KARAXYS_ALLOWED_ORIGINS", "https://karaxys.example.com")
	t.Setenv("KARAXYS_SECRET_KEY_B64", base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")))

	if err := ValidateProductionEnvironment(ServiceAPIServer); err != nil {
		t.Fatalf("unexpected production validation error: %v", err)
	}
}

func TestValidateProductionEnvironmentRejectsLocalhostOriginAndInvalidSecretKey(t *testing.T) {
	t.Setenv("KARAXYS_ENV", "production")
	t.Setenv("MONGO_URI", "mongodb://mongo.internal:27017")
	t.Setenv("MONGO_DB_NAME", "karaxys")
	t.Setenv("KARAXYS_API_KEY", "api-key-with-at-least-24-characters")
	t.Setenv("KARAXYS_AGENT_TOKEN", "agent-token-with-at-least-24-chars")
	t.Setenv("KARAXYS_ALLOWED_ORIGINS", "http://localhost:7000")
	t.Setenv("KARAXYS_SECRET_KEY_B64", "not-valid-base64")

	err := ValidateProductionEnvironment(ServiceAPIServer)
	if err == nil {
		t.Fatalf("expected production validation error")
	}
	if !strings.Contains(err.Error(), "KARAXYS_ALLOWED_ORIGINS") || !strings.Contains(err.Error(), "KARAXYS_SECRET_KEY_B64") {
		t.Fatalf("unexpected error: %v", err)
	}
}
