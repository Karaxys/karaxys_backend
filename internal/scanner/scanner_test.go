package scanner

import (
	"strings"
	"testing"

	"karaxys_backend/internal/core"
)

func TestBuildTemplateVarsUsesPollutedBodyAndFiltersHeaders(t *testing.T) {
	config := core.ScanConfig{
		TargetURL:    "http://localhost:3000",
		Method:       "POST",
		Path:         "/users/1",
		ManualAuth:   "Bearer secret",
		AttackMethod: "DELETE",
		Body:         `{"id":1}`,
		PollutedBody: `{"id":1,"id":2}`,
		Headers: map[string]string{
			"Authorization":  "Bearer secret",
			"Connection":     "keep-alive",
			"Content-Length": "8",
			"Content-Type":   "application/json",
			"Host":           "localhost:3000",
			"X-Trace-ID":     "abc",
		},
	}

	vars := BuildTemplateVars(config)
	joined := strings.Join(vars.Vars, "\n")
	if vars.Hostname != "localhost:3000" {
		t.Fatalf("unexpected hostname: %s", vars.Hostname)
	}
	if vars.BodyPayload != config.PollutedBody {
		t.Fatalf("expected polluted body, got %s", vars.BodyPayload)
	}
	if !strings.Contains(joined, "body_len=15") {
		t.Fatalf("expected body length var, got %s", joined)
	}
	if strings.Contains(vars.HeaderBlock, "Authorization") ||
		strings.Contains(vars.HeaderBlock, "Connection") ||
		strings.Contains(vars.HeaderBlock, "Content-Length") ||
		strings.Contains(vars.HeaderBlock, "Host") {
		t.Fatalf("sensitive/transport headers leaked into header block: %q", vars.HeaderBlock)
	}
	if vars.HeaderBlock != "Content-Type: application/json\nX-Trace-ID: abc\n" {
		t.Fatalf("unexpected deterministic header block: %q", vars.HeaderBlock)
	}
}

func TestExecutionTargetNormalizesLocalhostForDockerBridge(t *testing.T) {
	got := ExecutionTarget("http://localhost:3000/users")
	if got != "http://127.0.0.1:3000/users" {
		t.Fatalf("unexpected execution target: %s", got)
	}
}

func TestTemplateRegistryReturnsMetadataAndContent(t *testing.T) {
	registry := DefaultTemplateRegistry()
	metadata, err := registry.GetMetadata("BROKEN_USER_AUTH")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	if metadata.Category != CategoryAuth || metadata.Severity == "" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	content, err := registry.GetTemplate("BROKEN_USER_AUTH")
	if err != nil {
		t.Fatalf("get template: %v", err)
	}
	if !strings.Contains(content, "broken-user-auth") {
		t.Fatalf("unexpected template content")
	}
}

func TestTemplateRegistryListIsSortedAndComplete(t *testing.T) {
	metadata := DefaultTemplateRegistry().ListMetadata()
	if len(metadata) != len(defaultTemplates) {
		t.Fatalf("unexpected metadata count: %d", len(metadata))
	}
	for i := 1; i < len(metadata); i++ {
		if metadata[i-1].TestType > metadata[i].TestType {
			t.Fatalf("metadata not sorted: %s before %s", metadata[i-1].TestType, metadata[i].TestType)
		}
	}
	for _, item := range metadata {
		if item.TestType == "" || item.Filename == "" || item.Category == "" || item.Severity == "" {
			t.Fatalf("incomplete template metadata: %+v", item)
		}
	}
}

func TestTemplateRegistryRejectsUnknownType(t *testing.T) {
	_, err := DefaultTemplateRegistry().GetTemplate("UNKNOWN_TEST")
	if err == nil {
		t.Fatal("expected unknown template error")
	}
}
