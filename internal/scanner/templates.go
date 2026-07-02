package scanner

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	CategoryAccessControl  = "access_control"
	CategoryAuth           = "authentication"
	CategoryDiscovery      = "discovery"
	CategoryExposure       = "exposure"
	CategoryRedirect       = "redirect"
	CategoryInjection      = "injection"
	CategoryMisconfig      = "misconfiguration"
	CategoryCommunity      = "community"
	communityTemplatesRoot = "test_cases/community"
)

type TemplateMetadata struct {
	TestType             string        `json:"test_type"`
	Filename             string        `json:"filename"`
	Category             string        `json:"category"`
	Severity             string        `json:"severity"`
	RequiresAuth         bool          `json:"requires_auth"`
	RequiresAttackerAuth bool          `json:"requires_attacker_auth"`
	RequiredAuthRole     string        `json:"required_auth_role,omitempty"`
	RequiredSampleFields []string      `json:"required_sample_fields,omitempty"`
	Description          string        `json:"description,omitempty"`
	DynamicSeverity      *SeverityRule `json:"dynamic_severity,omitempty"`
}

// SeverityRule adjusts a finding's severity based on the response, so the same
// test type isn't always reported at a fixed severity regardless of what was
// actually exposed. All fields are optional; a nil rule leaves severity as-is.
type SeverityRule struct {
	// SensitiveMarkers: if the response body contains NONE of these
	// (case-insensitive), the finding is downgraded to DowngradeTo — e.g. a BOLA
	// hit that returns nothing sensitive is lower severity than one leaking PII.
	SensitiveMarkers []string `json:"sensitive_markers,omitempty"`
	DowngradeTo      string   `json:"downgrade_to,omitempty"`
}

type TemplateRegistry struct {
	templates map[string]TemplateMetadata
}

//go:embed test_cases
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
		DynamicSeverity: &SeverityRule{
			SensitiveMarkers: sensitiveDataMarkers,
			DowngradeTo:      "medium",
		},
	},
	{
		TestType:             "BFLA",
		Filename:             "test_cases/bfla-by-changing-http-method.yaml",
		Category:             CategoryAccessControl,
		Severity:             "high",
		RequiresAuth:         false,
		RequiredSampleFields: []string{"method", "path"},
		Description:          "Checks function-level authorization by changing the HTTP method.",
		DynamicSeverity: &SeverityRule{
			SensitiveMarkers: sensitiveDataMarkers,
			DowngradeTo:      "medium",
		},
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
	{
		TestType:             "REFLECTED_XSS",
		Filename:             "test_cases/reflected-xss.yaml",
		Category:             CategoryInjection,
		Severity:             "medium",
		RequiredSampleFields: []string{"path"},
		Description:          "Injects an HTML/script marker and checks for unescaped reflection.",
	},
	{
		TestType:             "SQL_INJECTION",
		Filename:             "test_cases/sql-injection.yaml",
		Category:             CategoryInjection,
		Severity:             "high",
		RequiredSampleFields: []string{"path"},
		Description:          "Error-based SQL injection: injects SQL metacharacters and detects database errors.",
	},
	{
		TestType:             "COMMAND_INJECTION",
		Filename:             "test_cases/command-injection.yaml",
		Category:             CategoryInjection,
		Severity:             "critical",
		RequiredSampleFields: []string{"path"},
		Description:          "Injects shell metacharacters and detects reflected command output.",
	},
	{
		TestType:             "SSRF",
		Filename:             "test_cases/ssrf.yaml",
		Category:             CategoryInjection,
		Severity:             "high",
		RequiredSampleFields: []string{"path"},
		Description:          "Injects internal/cloud-metadata URLs and detects reflected fetched content (in-band SSRF).",
	},
	{
		TestType:             "SSRF_BLIND_OOB",
		Filename:             "test_cases/ssrf-blind-oob.yaml",
		Category:             CategoryInjection,
		Severity:             "high",
		RequiredSampleFields: []string{"path"},
		Description:          "Blind SSRF via out-of-band Interactsh callback; requires OOB detection enabled.",
	},
	{
		TestType:             "CORS_MISCONFIGURATION",
		Filename:             "test_cases/cors-misconfiguration.yaml",
		Category:             CategoryMisconfig,
		Severity:             "medium",
		RequiredSampleFields: []string{"path"},
		Description:          "Checks whether the server reflects an attacker-controlled Origin with credentials enabled.",
	},
	{
		TestType:             "MASS_ASSIGNMENT",
		Filename:             "test_cases/mass-assignment.yaml",
		Category:             CategoryAccessControl,
		Severity:             "high",
		RequiresAuth:         true,
		RequiredSampleFields: []string{"path", "body"},
		Description:          "Injects privileged fields into a write request and checks whether they are accepted.",
	},
	{
		TestType:             "DEFAULT_CREDENTIALS",
		Filename:             "test_cases/default-credentials.yaml",
		Category:             CategoryAuth,
		Severity:             "high",
		RequiredSampleFields: []string{"path"},
		Description:          "Submits common default credential pairs to the auth endpoint and checks for successful login.",
	},
	{
		TestType:             "BOLA_CHAINED_ENUMERATION",
		Filename:             "test_cases/bola-chained-enumeration.yaml",
		Category:             CategoryAccessControl,
		Severity:             "high",
		RequiresAuth:         true,
		RequiresAttackerAuth: true,
		RequiredAuthRole:     "attacker",
		RequiredSampleFields: []string{"headers.Authorization", "path"},
		Description:          "Two-step BOLA: extracts an object id from a listing, then reads it directly with attacker credentials.",
		DynamicSeverity: &SeverityRule{
			SensitiveMarkers: sensitiveDataMarkers,
			DowngradeTo:      "medium",
		},
	},
}

// sensitiveDataMarkers are response substrings that indicate a finding actually
// exposed sensitive data, used by DynamicSeverity rules to keep severity high
// only when something meaningful leaked.
var sensitiveDataMarkers = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"ssn", "credit", "card_number", "\"email\"", "\"role\"", "authorization",
}

func DefaultTemplateRegistry() *TemplateRegistry {
	templates := make(map[string]TemplateMetadata, len(defaultTemplates))
	for _, metadata := range defaultTemplates {
		metadata.TestType = strings.TrimSpace(metadata.TestType)
		templates[metadata.TestType] = metadata
	}
	for _, metadata := range directoryTemplates() {
		// Hand-authored entries win over auto-discovered ones on collision.
		if _, exists := templates[metadata.TestType]; !exists {
			templates[metadata.TestType] = metadata
		}
	}
	return &TemplateRegistry{templates: templates}
}

// directoryTemplates auto-discovers self-contained community templates dropped
// into communityTemplatesRoot, deriving metadata from each template's own
// info block so no Go change is needed to add one. Only .yaml/.yml files are
// considered; anything that fails to parse or lacks an id is skipped rather
// than failing registry construction.
func directoryTemplates() []TemplateMetadata {
	var out []TemplateMetadata
	entries, err := fs.ReadDir(templateFS, communityTemplatesRoot)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if ext := strings.ToLower(path.Ext(name)); ext != ".yaml" && ext != ".yml" {
			continue
		}
		full := path.Join(communityTemplatesRoot, name)
		content, err := templateFS.ReadFile(full)
		if err != nil {
			continue
		}
		var doc struct {
			ID   string `yaml:"id"`
			Info struct {
				Name     string `yaml:"name"`
				Severity string `yaml:"severity"`
			} `yaml:"info"`
		}
		if err := yaml.Unmarshal(content, &doc); err != nil || strings.TrimSpace(doc.ID) == "" {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(doc.Info.Severity))
		if severity == "" {
			severity = "info"
		}
		out = append(out, TemplateMetadata{
			TestType:    communityTestType(doc.ID),
			Filename:    full,
			Category:    CategoryCommunity,
			Severity:    severity,
			Description: strings.TrimSpace(doc.Info.Name),
		})
	}
	return out
}

func communityTestType(id string) string {
	normalized := strings.ToUpper(strings.TrimSpace(id))
	normalized = strings.NewReplacer("-", "_", ".", "_", " ", "_", "/", "_").Replace(normalized)
	return "COMMUNITY_" + normalized
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
