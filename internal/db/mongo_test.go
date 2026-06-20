package db

import (
	"testing"
	"time"
)

func TestMongoIndexTimeoutFromEnv(t *testing.T) {
	t.Setenv("MONGO_INDEX_TIMEOUT_SECONDS", "120")

	if got := mongoIndexTimeout(); got != 120*time.Second {
		t.Fatalf("mongoIndexTimeout() = %s, want 2m0s", got)
	}
}

func TestMongoIndexTimeoutFallsBackForInvalidEnv(t *testing.T) {
	t.Setenv("MONGO_INDEX_TIMEOUT_SECONDS", "invalid")

	if got := mongoIndexTimeout(); got != defaultMongoIndexTimeout {
		t.Fatalf("mongoIndexTimeout() = %s, want %s", got, defaultMongoIndexTimeout)
	}
}
