package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	DefaultDeprecatedReason = "deprecated_endpoint"
	DefaultDeprecatedTag    = "lifecycle:deprecated"
	DefaultDeprecatedRisk   = "MEDIUM"
)

type EndpointRuleSet struct {
	Deprecated []EndpointRule `json:"deprecated"`
}

type EndpointRule struct {
	Name      string   `json:"name"`
	PathRegex string   `json:"path_regex"`
	Reason    string   `json:"reason,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	RiskLevel string   `json:"risk_level,omitempty"`
}

type Finding struct {
	Name      string
	Reason    string
	Tags      []string
	RiskLevel string
}

type CompiledEndpointRuleSet struct {
	deprecated []compiledRule
}

type compiledRule struct {
	rule EndpointRule
	re   *regexp.Regexp
}

func DefaultEndpointRuleSet() EndpointRuleSet {
	return EndpointRuleSet{
		Deprecated: []EndpointRule{
			{
				Name:      "explicit-deprecated-path",
				PathRegex: `(?i)(^|/)deprecated(/|$)`,
				Reason:    DefaultDeprecatedReason,
				Tags:      []string{DefaultDeprecatedTag},
				RiskLevel: DefaultDeprecatedRisk,
			},
			{
				Name:      "explicit-legacy-path",
				PathRegex: `(?i)(^|/)legacy(/|$)`,
				Reason:    DefaultDeprecatedReason,
				Tags:      []string{DefaultDeprecatedTag},
				RiskLevel: DefaultDeprecatedRisk,
			},
		},
	}
}

func LoadEndpointRuleSetFromEnv() (*CompiledEndpointRuleSet, error) {
	if path := strings.TrimSpace(os.Getenv("KARAXYS_ENDPOINT_RULES_FILE")); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read endpoint rules file: %w", err)
		}
		return CompileEndpointRuleSetBytes(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("KARAXYS_ENDPOINT_RULES_JSON")); raw != "" {
		return CompileEndpointRuleSetBytes([]byte(raw))
	}
	return CompileEndpointRuleSet(DefaultEndpointRuleSet())
}

func CompileEndpointRuleSetBytes(raw []byte) (*CompiledEndpointRuleSet, error) {
	var ruleSet EndpointRuleSet
	if err := json.Unmarshal(raw, &ruleSet); err != nil {
		return nil, fmt.Errorf("decode endpoint rules: %w", err)
	}
	return CompileEndpointRuleSet(ruleSet)
}

func CompileEndpointRuleSet(ruleSet EndpointRuleSet) (*CompiledEndpointRuleSet, error) {
	compiled := &CompiledEndpointRuleSet{}
	for idx, rule := range ruleSet.Deprecated {
		normalized, err := normalizeRule(rule, idx)
		if err != nil {
			return nil, err
		}
		re, err := regexp.Compile(normalized.PathRegex)
		if err != nil {
			return nil, fmt.Errorf("compile endpoint rule %q: %w", normalized.Name, err)
		}
		compiled.deprecated = append(compiled.deprecated, compiledRule{rule: normalized, re: re})
	}
	return compiled, nil
}

func (r *CompiledEndpointRuleSet) Evaluate(path string, pathPattern string) []Finding {
	if r == nil || len(r.deprecated) == 0 {
		return nil
	}
	targets := uniqueNonEmpty(path, pathPattern)
	var findings []Finding
	seen := map[string]bool{}
	for _, rule := range r.deprecated {
		for _, target := range targets {
			if !rule.re.MatchString(target) {
				continue
			}
			key := "deprecated:" + rule.rule.Name
			if seen[key] {
				break
			}
			seen[key] = true
			findings = append(findings, Finding{
				Name:      rule.rule.Name,
				Reason:    rule.rule.Reason,
				Tags:      append([]string(nil), rule.rule.Tags...),
				RiskLevel: rule.rule.RiskLevel,
			})
			break
		}
	}
	return findings
}

func normalizeRule(rule EndpointRule, idx int) (EndpointRule, error) {
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("deprecated-%d", idx+1)
	}
	rule.PathRegex = strings.TrimSpace(rule.PathRegex)
	if rule.PathRegex == "" {
		return EndpointRule{}, fmt.Errorf("endpoint rule %q missing path_regex", rule.Name)
	}
	rule.Reason = strings.TrimSpace(rule.Reason)
	if rule.Reason == "" {
		rule.Reason = DefaultDeprecatedReason
	}
	rule.Tags = uniqueStrings(rule.Tags)
	if len(rule.Tags) == 0 {
		rule.Tags = []string{DefaultDeprecatedTag}
	}
	rule.RiskLevel = normalizeRiskLevel(rule.RiskLevel)
	if rule.RiskLevel == "" {
		rule.RiskLevel = DefaultDeprecatedRisk
	}
	return rule, nil
}

func normalizeRiskLevel(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return strings.ToUpper(strings.TrimSpace(value))
	default:
		return ""
	}
}

func uniqueNonEmpty(values ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
