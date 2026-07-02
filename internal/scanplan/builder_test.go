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
	if !strings.Contains(err.Error(), "requires an attacker auth context") {
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

func TestBuildScanConfigUsesAttackerAuthContextForBOLA(t *testing.T) {
	inventory := testInventory()
	inventory.SampleHeaders["Authorization"] = []string{redact.Marker}

	config, err := BuildScanConfigWithAuthContexts("http://api.example.local", inventory, map[string]string{
		AuthRoleAttacker: "Bearer attacker-context",
		AuthRoleVictim:   "Bearer victim-context",
	}, "", "", testBOLA)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	if config.ManualAuth != "Bearer attacker-context" {
		t.Fatalf("unexpected manual auth: %s", config.ManualAuth)
	}
}

func TestBuildScanConfigUsesVictimAuthContextForJWTManipulation(t *testing.T) {
	inventory := testInventory()
	inventory.SampleHeaders["Authorization"] = []string{redact.Marker}
	victimToken := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2aWN0aW0ifQ.signature"

	config, err := BuildScanConfigWithAuthContexts("http://api.example.local", inventory, map[string]string{
		AuthRoleAttacker: "Bearer attacker-context",
		AuthRoleVictim:   victimToken,
	}, "", "", testJWTInvalidSignature)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	if config.ManualAuth == victimToken || !strings.HasPrefix(config.ManualAuth, "Bearer ") {
		t.Fatalf("expected tampered victim token, got %s", config.ManualAuth)
	}
}

func TestBuildScanConfigRejectsUnknownAuthContextRole(t *testing.T) {
	inventory := testInventory()
	inventory.SampleHeaders["Authorization"] = []string{redact.Marker}

	_, err := BuildScanConfigWithAuthContexts("http://api.example.local", inventory, map[string]string{
		"owner": "Bearer unsupported-role",
	}, "", "", testBOLA)
	if err == nil {
		t.Fatal("expected missing attacker context to fail")
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

func TestBuildScanConfigInjectsPayloadForSQLInjection(t *testing.T) {
	inventory := testInventory()
	inventory.SampleReqBody = `{"username":"alice","age":30}`
	inventory.SampleRespBody = `{"ok":true}`
	inventory.StatusCodes = []int{200}

	config, err := BuildScanConfig("http://api.example.local", inventory, "Bearer t", "", testSQLInjection)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	// The payload is stitched into the string field (JSON-escaped on marshal),
	// replacing the original value; the distinctive "kx" marker survives escaping.
	if strings.Contains(config.PollutedBody, `"alice"`) {
		t.Fatalf("string field value should be replaced by payload: %s", config.PollutedBody)
	}
	if !strings.Contains(config.PollutedBody, "kx") {
		t.Fatalf("expected SQLi payload marker in polluted body, got: %s", config.PollutedBody)
	}
	// Numeric field left intact.
	if !strings.Contains(config.PollutedBody, `"age":30`) {
		t.Fatalf("numeric field should be preserved: %s", config.PollutedBody)
	}
	if config.OriginalResponseBody != `{"ok":true}` || config.OriginalStatusCode != 200 {
		t.Fatalf("baseline response not populated: body=%q status=%d", config.OriginalResponseBody, config.OriginalStatusCode)
	}
}

func TestBuildScanConfigAddsPrivilegedFieldsForMassAssignment(t *testing.T) {
	inventory := testInventory()
	inventory.SampleReqBody = `{"name":"bob"}`

	config, err := BuildScanConfig("http://api.example.local", inventory, "Bearer t", "", testMassAssignment)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	if !strings.Contains(config.PollutedBody, "kx_is_admin") || !strings.Contains(config.PollutedBody, "kx_role") {
		t.Fatalf("expected injected privileged fields, got: %s", config.PollutedBody)
	}
	if !strings.Contains(config.PollutedBody, `"name":"bob"`) {
		t.Fatalf("original field should be preserved: %s", config.PollutedBody)
	}
}

func TestBuildScanConfigInjectsPayloadIntoQueryForXSS(t *testing.T) {
	inventory := testInventory()
	inventory.Method = "GET"
	inventory.OriginalPath = "/search?q=foo&page=2"
	inventory.SampleReqBody = ""

	config, err := BuildScanConfig("http://api.example.local", inventory, "Bearer t", "", testReflectedXSS)
	if err != nil {
		t.Fatalf("build scan config: %v", err)
	}
	if !strings.HasPrefix(config.Path, "/search?") {
		t.Fatalf("expected query injection to preserve base path, got: %s", config.Path)
	}
	// Existing params are overwritten with the payload and a fallback param added.
	if !strings.Contains(config.Path, "kx_input=") {
		t.Fatalf("expected fallback injection param, got: %s", config.Path)
	}
	if strings.Contains(config.Path, "q=foo") {
		t.Fatalf("existing query value should be replaced by payload, got: %s", config.Path)
	}
	if !strings.Contains(config.Path, "q=") || !strings.Contains(config.Path, "page=") {
		t.Fatalf("existing query keys should be preserved, got: %s", config.Path)
	}
}

func TestBuildInjectionPathAddsQueryWhenNoneExists(t *testing.T) {
	out := buildInjectionPath("/items", "PAY LOAD")
	if !strings.HasPrefix(out, "/items?") {
		t.Fatalf("expected query appended to bare path, got: %s", out)
	}
	// Payload must be URL-encoded (space becomes + or %20).
	if strings.Contains(out, "PAY LOAD") {
		t.Fatalf("payload should be url-encoded, got: %s", out)
	}
}

func TestBuildInjectionBodyFallsBackForNonJSON(t *testing.T) {
	out := buildInjectionBody("not json at all", "PAYLOAD")
	if !strings.Contains(out, "kx_input") || !strings.Contains(out, "PAYLOAD") {
		t.Fatalf("unexpected fallback body: %s", out)
	}
}
