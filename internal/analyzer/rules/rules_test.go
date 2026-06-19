package rules

import "testing"

func TestDefaultEndpointRuleSetDetectsExplicitDeprecatedPaths(t *testing.T) {
	ruleSet, err := CompileEndpointRuleSet(DefaultEndpointRuleSet())
	if err != nil {
		t.Fatalf("compile default rules: %v", err)
	}

	findings := ruleSet.Evaluate("/api/deprecated/users", "/api/deprecated/users")
	if len(findings) != 1 {
		t.Fatalf("expected deprecated finding, got %#v", findings)
	}
	if findings[0].Reason != DefaultDeprecatedReason || findings[0].RiskLevel != DefaultDeprecatedRisk {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}

	if findings := ruleSet.Evaluate("/api/v1/users", "/api/v1/users"); len(findings) != 0 {
		t.Fatalf("unexpected finding for normal path: %#v", findings)
	}
}

func TestCompileEndpointRuleSetBytesValidatesRegex(t *testing.T) {
	_, err := CompileEndpointRuleSetBytes([]byte(`{"deprecated":[{"name":"bad","path_regex":"["}]}`))
	if err == nil {
		t.Fatal("expected invalid regex to fail")
	}
}

func TestEndpointRuleSetSupportsConfiguredDeprecatedVersion(t *testing.T) {
	ruleSet, err := CompileEndpointRuleSetBytes([]byte(`{
		"deprecated": [
			{
				"name": "v1-retired",
				"path_regex": "^/api/v1/",
				"reason": "deprecated_version:v1",
				"tags": ["lifecycle:deprecated", "version:v1"],
				"risk_level": "HIGH"
			}
		]
	}`))
	if err != nil {
		t.Fatalf("compile configured rules: %v", err)
	}

	findings := ruleSet.Evaluate("/api/v1/users/123", "/api/v1/users/{user_id}")
	if len(findings) != 1 {
		t.Fatalf("expected configured finding, got %#v", findings)
	}
	if findings[0].Name != "v1-retired" || findings[0].Reason != "deprecated_version:v1" || findings[0].RiskLevel != "HIGH" {
		t.Fatalf("unexpected configured finding: %#v", findings[0])
	}
	if len(findings[0].Tags) != 2 || findings[0].Tags[1] != "version:v1" {
		t.Fatalf("unexpected tags: %#v", findings[0].Tags)
	}
}
