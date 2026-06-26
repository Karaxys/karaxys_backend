package scanner

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

const (
	CategoryAccessControl = "access_control"
	CategoryAuth          = "authentication"
	CategoryDiscovery     = "discovery"
	CategoryExposure      = "exposure"
	CategoryRedirect      = "redirect"
)

type TemplateMetadata struct {
	TestType             string   `json:"test_type"`
	Filename             string   `json:"filename"`
	Category             string   `json:"category"`
	Severity             string   `json:"severity"`
	RequiresAuth         bool     `json:"requires_auth"`
	RequiresAttackerAuth bool     `json:"requires_attacker_auth"`
	RequiredAuthRole     string   `json:"required_auth_role,omitempty"`
	RequiredSampleFields []string `json:"required_sample_fields,omitempty"`
	Description          string   `json:"description,omitempty"`
}

type TemplateRegistry struct {
	templates map[string]TemplateMetadata
}

//go:embed test_cases/*.yaml
var templateFS embed.FS

var defaultTemplates = []TemplateMetadata{
	{
		TestType:             "BOLA",
		Filename:             "test_cases/bola-by-changing-auth-token.yaml",
		Category:             CategoryAccessControl,
		Severity:             "high",
		RequiresAuth:         true,
		RequiresAttackerAuth: true,
		RequiredAuthRole:     "attacker",
		RequiredSampleFields: []string{"headers.Authorization", "path"},
		Description:          "Checks object-level authorization by replaying a request with attacker credentials.",
	},
	{
		TestType:             "BFLA",
		Filename:             "test_cases/bfla-by-changing-http-method.yaml",
		Category:             CategoryAccessControl,
		Severity:             "high",
		RequiresAuth:         false,
		RequiredSampleFields: []string{"method", "path"},
		Description:          "Checks function-level authorization by changing the HTTP method.",
	},
	{
		TestType:             "BROKEN_USER_AUTH",
		Filename:             "test_cases/broken-user-authentication.yaml",
		Category:             CategoryAuth,
		Severity:             "high",
		RequiresAuth:         false,
		RequiredSampleFields: []string{"path"},
		Description:          "Checks whether authentication-sensitive endpoints accept missing credentials.",
	},
	{
		TestType:             "BOLA_PARAMETER_POLLUTION",
		Filename:             "test_cases/bola-by-parameter-pollution.yaml",
		Category:             CategoryAccessControl,
		Severity:             "high",
		RequiresAuth:         true,
		RequiresAttackerAuth: true,
		RequiredAuthRole:     "attacker",
		RequiredSampleFields: []string{"headers.Authorization", "body"},
		Description:          "Checks object-level authorization by injecting duplicate object identifiers.",
	},
	{
		TestType:             "SWAGGER_CHECK",
		Filename:             "test_cases/swagger-check.yaml",
		Category:             CategoryDiscovery,
		Severity:             "medium",
		RequiredSampleFields: []string{"base_url"},
		Description:          "Checks for exposed OpenAPI or Swagger documentation endpoints.",
	},
	{
		TestType:             "JWT_NONE_ALGO",
		Filename:             "test_cases/jwt-none-algo.yaml",
		Category:             CategoryAuth,
		Severity:             "high",
		RequiresAuth:         true,
		RequiredAuthRole:     "victim",
		RequiredSampleFields: []string{"headers.Authorization"},
		Description:          "Checks whether JWT none-algorithm tokens are accepted.",
	},
	{
		TestType:             "JWT_INVALID_SIGNATURE",
		Filename:             "test_cases/jwt-invalid-signature.yaml",
		Category:             CategoryAuth,
		Severity:             "high",
		RequiresAuth:         true,
		RequiredAuthRole:     "victim",
		RequiredSampleFields: []string{"headers.Authorization"},
		Description:          "Checks whether tampered JWT signatures are accepted.",
	},
	{
		TestType:             "OPEN_REDIRECT",
		Filename:             "test_cases/open-redirect.yaml",
		Category:             CategoryRedirect,
		Severity:             "medium",
		RequiredSampleFields: []string{"path"},
		Description:          "Checks redirect parameters for externally controlled redirects.",
	},
	{
		TestType:             "EXPOSED_METRICS",
		Filename:             "test_cases/exposed-metrics.yaml",
		Category:             CategoryExposure,
		Severity:             "medium",
		RequiredSampleFields: []string{"base_url"},
		Description:          "Checks for exposed operational metrics endpoints.",
	},
}

func DefaultTemplateRegistry() *TemplateRegistry {
	templates := make(map[string]TemplateMetadata, len(defaultTemplates))
	for _, metadata := range defaultTemplates {
		metadata.TestType = strings.TrimSpace(metadata.TestType)
		templates[metadata.TestType] = metadata
	}
	return &TemplateRegistry{templates: templates}
}

func (r *TemplateRegistry) GetTemplate(testType string) (string, error) {
	metadata, err := r.GetMetadata(testType)
	if err != nil {
		return "", err
	}
	content, err := templateFS.ReadFile(metadata.Filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (r *TemplateRegistry) GetMetadata(testType string) (TemplateMetadata, error) {
	if r == nil {
		return TemplateMetadata{}, fmt.Errorf("template registry is required")
	}
	metadata, ok := r.templates[strings.TrimSpace(testType)]
	if !ok {
		return TemplateMetadata{}, fmt.Errorf("unknown test type")
	}
	return metadata, nil
}

func (r *TemplateRegistry) ListMetadata() []TemplateMetadata {
	if r == nil {
		return nil
	}
	out := make([]TemplateMetadata, 0, len(r.templates))
	for _, metadata := range r.templates {
		out = append(out, metadata)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TestType < out[j].TestType
	})
	return out
}

func GetTemplate(testType string) (string, error) {
	return DefaultTemplateRegistry().GetTemplate(testType)
}
