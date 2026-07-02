package scanplan

import (
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/scanner"
	"sort"
	"strings"
)

// ApplicableTestTypes returns the test types worth running against a single
// endpoint, given what the inventory record carries and which auth contexts are
// available. Tests whose required sample fields are missing (e.g. body injection
// against an endpoint with no body) or whose auth prerequisites are unmet are
// filtered out, so a suite scan runs only meaningful checks instead of every
// registered template blindly.
func ApplicableTestTypes(registry *scanner.TemplateRegistry, inventory *core.ApiInventory, authContexts map[string]string, legacyManualToken string) []string {
	if registry == nil || inventory == nil {
		return nil
	}
	contexts := normalizeAuthContexts(authContexts)
	hasAttacker := usableToken(legacyManualToken) || pickContextToken(contexts, AuthRoleAttacker) != ""
	hasAnyAuth := hasAttacker ||
		pickContextToken(contexts, AuthRoleVictim) != "" ||
		pickContextToken(contexts, AuthRoleAdmin) != "" ||
		sampleHasAuthorization(inventory)

	out := make([]string, 0)
	for _, meta := range registry.ListMetadata() {
		if !endpointSatisfiesFields(meta, inventory, hasAnyAuth) {
			continue
		}
		if meta.RequiresAttackerAuth && !hasAttacker {
			continue
		}
		if meta.RequiresAuth && !hasAnyAuth {
			continue
		}
		out = append(out, meta.TestType)
	}
	sort.Strings(out)
	return out
}

func endpointSatisfiesFields(meta scanner.TemplateMetadata, inventory *core.ApiInventory, hasAnyAuth bool) bool {
	for _, field := range meta.RequiredSampleFields {
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "path":
			if strings.TrimSpace(inventory.OriginalPath) == "" {
				return false
			}
		case "method":
			if strings.TrimSpace(inventory.Method) == "" {
				return false
			}
		case "base_url":
			if strings.TrimSpace(inventory.BaseURL) == "" {
				return false
			}
		case "body":
			if !endpointCarriesBody(inventory) {
				return false
			}
		case "headers.authorization":
			if !hasAnyAuth {
				return false
			}
		}
	}
	return true
}

func endpointCarriesBody(inventory *core.ApiInventory) bool {
	body := strings.TrimSpace(inventory.SampleReqBody)
	if body != "" && body != "{}" {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(inventory.Method)) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

func sampleHasAuthorization(inventory *core.ApiInventory) bool {
	for _, value := range inventory.SampleHeaders["Authorization"] {
		if usableToken(value) {
			return true
		}
	}
	return false
}
