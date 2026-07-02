package api

import (
	"karaxys_backend/internal/scanner"
	"net/http"
	"testing"
)

func TestRegisterRoutesNoPatternConflict(t *testing.T) {
	// Go's ServeMux panics at registration on conflicting wildcard patterns
	// (e.g. /v1/scans/{id}/events vs a naive /v1/scans/suites/{id}). This guards
	// against reintroducing such a conflict.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked: %v", r)
		}
	}()
	(&Server{}).registerRoutes(http.NewServeMux())
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func TestIntersectTestTypesFiltersAndReportsSkipped(t *testing.T) {
	selected, skipped := intersectTestTypes(
		[]string{"BOLA", "SSRF", "BOLA", "MASS_ASSIGNMENT"},
		[]string{"SSRF", "BOLA"},
	)
	if len(selected) != 2 || selected[0] != "BOLA" || selected[1] != "SSRF" {
		t.Fatalf("unexpected selected (order/dedup): %v", selected)
	}
	if len(skipped) != 1 || skipped[0] != "MASS_ASSIGNMENT" {
		t.Fatalf("unexpected skipped: %v", skipped)
	}
}

func TestSelectSuiteTestTypesPresetIntersectsApplicable(t *testing.T) {
	registry := scanner.DefaultTemplateRegistry()
	applicable := []string{"BROKEN_USER_AUTH", "JWT_NONE_ALGO"} // no DEFAULT_CREDENTIALS

	selected, skipped, err := selectSuiteTestTypes(registry, ScanSuiteRequest{Suite: "authentication"}, applicable)
	if err != nil {
		t.Fatalf("resolve preset: %v", err)
	}
	if !contains(selected, "BROKEN_USER_AUTH") || !contains(selected, "JWT_NONE_ALGO") {
		t.Fatalf("expected applicable auth tests selected, got %v", selected)
	}
	if contains(selected, "DEFAULT_CREDENTIALS") {
		t.Fatalf("inapplicable preset member should not be selected: %v", selected)
	}
	if !contains(skipped, "DEFAULT_CREDENTIALS") || !contains(skipped, "JWT_INVALID_SIGNATURE") {
		t.Fatalf("expected inapplicable preset members reported skipped, got %v", skipped)
	}
}

func TestSelectSuiteTestTypesFullReturnsAllApplicable(t *testing.T) {
	registry := scanner.DefaultTemplateRegistry()
	applicable := []string{"SSRF", "BOLA"}
	selected, skipped, err := selectSuiteTestTypes(registry, ScanSuiteRequest{Suite: "FULL"}, applicable)
	if err != nil {
		t.Fatalf("full suite: %v", err)
	}
	if len(selected) != 2 || len(skipped) != 0 {
		t.Fatalf("FULL should return all applicable with no skips, got selected=%v skipped=%v", selected, skipped)
	}
}

func TestSelectSuiteTestTypesUnknownPreset(t *testing.T) {
	registry := scanner.DefaultTemplateRegistry()
	if _, _, err := selectSuiteTestTypes(registry, ScanSuiteRequest{Suite: "does-not-exist"}, []string{"SSRF"}); err == nil {
		t.Fatal("expected unknown preset to error")
	}
}
