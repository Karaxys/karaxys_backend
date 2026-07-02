package scanplan

import (
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/scanner"
	"testing"
)

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func TestApplicableTestTypesGetEndpointNoAuth(t *testing.T) {
	registry := scanner.DefaultTemplateRegistry()
	inv := &core.ApiInventory{
		Method:       "GET",
		OriginalPath: "/search",
		BaseURL:      "http://api.example.local",
	}
	applicable := ApplicableTestTypes(registry, inv, nil, "")

	// Path/base_url tests apply; injection now reaches GET via query params.
	for _, want := range []string{"REFLECTED_XSS", "SQL_INJECTION", "SSRF", "SWAGGER_CHECK", "BROKEN_USER_AUTH"} {
		if !contains(applicable, want) {
			t.Fatalf("expected %s to be applicable, got %v", want, applicable)
		}
	}
	// Attacker-auth tests must be excluded without an attacker token.
	for _, notWant := range []string{"BOLA", "BOLA_CHAINED_ENUMERATION"} {
		if contains(applicable, notWant) {
			t.Fatalf("did not expect %s without attacker auth, got %v", notWant, applicable)
		}
	}
	// Body-only tests excluded on a GET with no body.
	if contains(applicable, "MASS_ASSIGNMENT") {
		t.Fatalf("mass assignment should not apply to a bodyless GET: %v", applicable)
	}
}

func TestApplicableTestTypesWithAttackerAndBody(t *testing.T) {
	registry := scanner.DefaultTemplateRegistry()
	inv := &core.ApiInventory{
		Method:        "POST",
		OriginalPath:  "/orders",
		BaseURL:       "http://api.example.local",
		SampleReqBody: `{"item":"x"}`,
		SampleHeaders: map[string][]string{"Authorization": {"Bearer sample"}},
	}
	applicable := ApplicableTestTypes(registry, inv, map[string]string{AuthRoleAttacker: "Bearer attacker"}, "")

	for _, want := range []string{"BOLA", "MASS_ASSIGNMENT", "BFLA"} {
		if !contains(applicable, want) {
			t.Fatalf("expected %s to be applicable, got %v", want, applicable)
		}
	}
}
