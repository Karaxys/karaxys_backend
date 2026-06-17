package config

import (
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
