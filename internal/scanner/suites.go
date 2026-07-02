package scanner

import "strings"

// SuitePreset is a named group of test types run together as one suite. Presets
// map to the OWASP API Security Top 10 risk categories so an operator can launch
// broad, well-understood coverage without hand-picking individual tests. A nil
// TestTypes list means "every registered test type applicable to the endpoint".
type SuitePreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	TestTypes   []string `json:"test_types"`
}

// suitePresets are ordered from broadest to most focused. The OWASP references
// in each description follow the OWASP API Security Top 10 (2023).
var suitePresets = []SuitePreset{
	{
		ID:          "OWASP_API_TOP_10",
		Name:        "OWASP API Security Top 10",
		Description: "Broad coverage mapped across the OWASP API Security Top 10 risk categories.",
		TestTypes: []string{
			"BOLA", "BOLA_PARAMETER_POLLUTION", "BOLA_CHAINED_ENUMERATION",
			"BROKEN_USER_AUTH", "JWT_NONE_ALGO", "JWT_INVALID_SIGNATURE", "DEFAULT_CREDENTIALS",
			"MASS_ASSIGNMENT", "BFLA",
			"SSRF", "SSRF_BLIND_OOB",
			"CORS_MISCONFIGURATION", "EXPOSED_METRICS", "SWAGGER_CHECK",
			"REFLECTED_XSS", "SQL_INJECTION", "COMMAND_INJECTION", "OPEN_REDIRECT",
		},
	},
	{
		ID:          "ACCESS_CONTROL",
		Name:        "Broken Access Control",
		Description: "Object- and function-level authorization checks (OWASP API1/API3/API5).",
		TestTypes:   []string{"BOLA", "BOLA_PARAMETER_POLLUTION", "BOLA_CHAINED_ENUMERATION", "BFLA", "MASS_ASSIGNMENT"},
	},
	{
		ID:          "AUTHENTICATION",
		Name:        "Broken Authentication",
		Description: "Anonymous access, JWT flaws and default credentials (OWASP API2).",
		TestTypes:   []string{"BROKEN_USER_AUTH", "JWT_NONE_ALGO", "JWT_INVALID_SIGNATURE", "DEFAULT_CREDENTIALS"},
	},
	{
		ID:          "INJECTION",
		Name:        "Injection",
		Description: "Reflected XSS, SQL injection, command injection and open redirect.",
		TestTypes:   []string{"REFLECTED_XSS", "SQL_INJECTION", "COMMAND_INJECTION", "OPEN_REDIRECT"},
	},
	{
		ID:          "SSRF",
		Name:        "Server-Side Request Forgery",
		Description: "In-band and blind out-of-band SSRF (OWASP API7).",
		TestTypes:   []string{"SSRF", "SSRF_BLIND_OOB"},
	},
	{
		ID:          "MISCONFIGURATION",
		Name:        "Security Misconfiguration",
		Description: "CORS, exposed metrics/documentation and inventory exposure (OWASP API8/API9).",
		TestTypes:   []string{"CORS_MISCONFIGURATION", "EXPOSED_METRICS", "SWAGGER_CHECK"},
	},
	{
		ID:          "FULL",
		Name:        "Full Scan",
		Description: "Every registered test type applicable to the endpoint, including community templates.",
		TestTypes:   nil,
	},
}

// SuitePresets returns a copy of the built-in suite presets.
func SuitePresets() []SuitePreset {
	out := make([]SuitePreset, len(suitePresets))
	copy(out, suitePresets)
	return out
}

// LookupSuitePreset resolves a preset by id (case-insensitive).
func LookupSuitePreset(id string) (SuitePreset, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	for _, preset := range suitePresets {
		if preset.ID == id {
			return preset, true
		}
	}
	return SuitePreset{}, false
}

// FilterRegistered keeps only the test types that exist in this registry,
// preserving order. Used so a preset that references a template not present in a
// given build silently omits it rather than creating a job that cannot run.
func (r *TemplateRegistry) FilterRegistered(testTypes []string) []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(testTypes))
	for _, testType := range testTypes {
		if _, ok := r.templates[strings.TrimSpace(testType)]; ok {
			out = append(out, testType)
		}
	}
	return out
}
