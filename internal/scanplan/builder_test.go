package scanplan

import (
	"strings"
	"testing"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/redact"
)

func TestBuildScanConfigRequiresUsableTokenForBOLA(t *testing.T) {
	inventory := testInventory()
	inventory.SampleHeaders["Authorization"] = []string{redact.Marker}

	_, err := BuildScanConfig("http://api.example.local", inventory, "", "", testBOLA)
	if err == nil {
		t.Fatalf("expected BOLA to reject redacted sample auth")
	}
	if !strings.Contains(err.Error(), "requires an attacker token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildScanConfigUsesManualTokenForAuthTests(t *testing.T) {
	inventory := testInventory()
	inventory.SampleHeaders["Authorization"] = []string{redact.Marker}

	config, err := BuildScanConfig("http://api.example.local", inventory, "Bearer attacker-token", "", testBOLA)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	if config.ManualAuth != "Bearer attacker-token" {
		t.Fatalf("unexpected manual auth: %s", config.ManualAuth)
	}
}

func TestBuildScanConfigIgnoresRedactedTokenForOptionalAuth(t *testing.T) {
	inventory := testInventory()
	inventory.SampleHeaders["Authorization"] = []string{redact.Marker}

	config, err := BuildScanConfig("http://api.example.local", inventory, "", "", testSwaggerCheck)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	if config.ManualAuth != "" {
		t.Fatalf("expected no manual auth, got %q", config.ManualAuth)
	}
}

func testInventory() *core.ApiInventory {
	return &core.ApiInventory{
		Method:       "POST",
		OriginalPath: "/users/1",
		SampleHeaders: map[string][]string{
			"Authorization": {"Bearer sample-token"},
		},
		SampleReqBody: `{"id":1}`,
	}
}
