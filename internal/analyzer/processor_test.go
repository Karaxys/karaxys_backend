package analyzer

import (
	"testing"

	"karaxys_backend/internal/analyzer/endpoint"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/redact"
)

func TestProcessorHelpersSanitizeMongoFieldKeys(t *testing.T) {
	if got := mongoFieldKey("X.Custom$Header"); got != "X_Custom_Header" {
		t.Fatalf("unexpected mongo key: %s", got)
	}

	schema := headerSchema(map[string][]string{
		"X.Custom$Header": {"a", "b"},
		"Authorization":   {"Bearer secret"},
	})
	if schema["X_Custom_Header"] != "array<string>" {
		t.Fatalf("unexpected custom header schema: %#v", schema)
	}
	if schema["Authorization"] != "string" {
		t.Fatalf("unexpected auth header schema: %#v", schema)
	}
}

func TestProcessorHelpersExtractStatusAndContentTypes(t *testing.T) {
	logEntry := core.TrafficLog{
		RespStatus: "201 Created",
		ReqHeaders: map[string][]string{
			"Content-Type": {"application/json; charset=utf-8"},
		},
		RespHeaders: map[string][]string{
			"content-type": {"application/problem+json"},
		},
	}
	if got := responseStatusCode(logEntry); got != 201 {
		t.Fatalf("unexpected status code: %d", got)
	}
	contentTypes := observedContentTypes(logEntry)
	if len(contentTypes) != 2 || contentTypes[0] != "application/json" || contentTypes[1] != "application/problem+json" {
		t.Fatalf("unexpected content types: %#v", contentTypes)
	}
}

func TestParameterObservationsIncludePathQueryHeadersAndBodySchemas(t *testing.T) {
	pathParams := []endpoint.ParameterObservation{
		{Name: "user_id", Location: endpoint.LocationPath, Value: "123", DataType: "integer"},
	}
	logEntry := core.TrafficLog{
		URL: "https://api.example.com/v1/users/123?expand=true",
		ReqHeaders: map[string][]string{
			"Authorization": {"Bearer secret"},
			"Cookie":        {"session_id=abc123"},
		},
	}
	redactedLogEntry := redact.TrafficLog(logEntry)
	observations := parameterObservations(pathParams, logEntry, redactedLogEntry, map[string]string{"email": "string"}, map[string]string{"token": "string"})

	seen := map[string]bool{}
	for _, observation := range observations {
		seen[observation.Location+":"+observation.Name] = true
	}
	for _, expected := range []string{
		endpoint.LocationPath + ":user_id",
		endpoint.LocationQuery + ":expand",
		endpoint.LocationCookie + ":session_id",
		endpoint.LocationHeader + ":Authorization",
		endpoint.LocationRequestBody + ":email",
		endpoint.LocationResponseBody + ":token",
	} {
		if !seen[expected] {
			t.Fatalf("missing observation %s in %#v", expected, observations)
		}
	}
}

func TestRiskReasonsAndTagsTrackResponseSensitivityAndKeywords(t *testing.T) {
	reasons := calculateRiskReasons([]string{"EMAIL"}, []string{"EMAIL"}, false, 500, "/admin/users")
	seenReasons := map[string]bool{}
	for _, reason := range reasons {
		seenReasons[reason] = true
	}
	for _, expected := range []string{"sensitive_data_detected", "sensitive_data_in_response", "no_auth_observed", "server_error_observed", "keyword:admin"} {
		if !seenReasons[expected] {
			t.Fatalf("missing reason %s in %#v", expected, reasons)
		}
	}

	tags := endpointTags(core.TrafficLog{CaptureSource: "ebpf", Path: "/debug/openapi.json"}, false, []string{"EMAIL"}, []string{"EMAIL"})
	seenTags := map[string]bool{}
	for _, tag := range tags {
		seenTags[tag] = true
	}
	for _, expected := range []string{"capture_source:ebpf", "auth:not_observed", "sensitive_data:response", "keyword:debug", "keyword:openapi"} {
		if !seenTags[expected] {
			t.Fatalf("missing tag %s in %#v", expected, tags)
		}
	}
}

func TestRedactedParameterSampleMasksSensitiveValues(t *testing.T) {
	if got := redactedParameterSample("alice@example.com", []string{"EMAIL"}); got != redact.Marker {
		t.Fatalf("expected sensitive parameter sample to be redacted, got %s", got)
	}
	if got := redactedParameterSample("plain-value", nil); got != "plain-value" {
		t.Fatalf("expected non-sensitive sample to be preserved, got %s", got)
	}
}
