package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"karaxys_backend/internal/analyzer/endpoint"
	lifecyclerules "karaxys_backend/internal/analyzer/rules"
	"karaxys_backend/internal/contracts"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/security/redact"

	"go.mongodb.org/mongo-driver/bson"
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

func TestTrafficSampleFromLogUsesRedactedExcerptAndHashes(t *testing.T) {
	raw := core.TrafficLog{
		TenantID:       "tenant-1",
		ProjectID:      "project-1",
		AgentID:        "agent-1",
		CaptureSource:  "ebpf",
		CaptureMode:    "kernel",
		Method:         "post",
		URL:            "https://api.example.com/users/123?token=secret-token-value",
		Host:           "api.example.com",
		Path:           "/users/123",
		ReqHeaders:     map[string][]string{"Authorization": {"Bearer secret-token-value"}},
		ReqBody:        `{"password":"secret","bio":"` + strings.Repeat("a", maxStoredSampleBodyBytes+20) + `"}`,
		RespStatus:     "200 OK",
		RespStatusCode: 200,
		RespHeaders:    map[string][]string{"Set-Cookie": {"session=secret"}},
		RespBody:       `{"email":"alice@example.com"}`,
		CreatedAt:      time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC),
	}
	redacted := redact.TrafficLog(raw)
	sample := trafficSampleFromLog(raw, redacted, "https://api.example.com", "api.example.com", "/users/{user_id}", "fingerprint", []string{"EMAIL"}, []string{"auth:observed"}, time.Date(2026, 6, 19, 1, 3, 0, 0, time.UTC))

	if sample.SchemaVersion != core.TrafficSampleSchemaV1 {
		t.Fatalf("unexpected schema: %s", sample.SchemaVersion)
	}
	if sample.ReqHeaders["Authorization"][0] != redact.Marker {
		t.Fatalf("request authorization header was not redacted: %#v", sample.ReqHeaders)
	}
	if sample.RespHeaders["Set-Cookie"][0] != redact.Marker {
		t.Fatalf("response cookie header was not redacted: %#v", sample.RespHeaders)
	}
	if strings.Contains(sample.URL, "secret-token-value") {
		t.Fatalf("sample URL contains raw secret: %s", sample.URL)
	}
	if !sample.ReqBodyTruncated || len(sample.ReqBody) != maxStoredSampleBodyBytes {
		t.Fatalf("expected request body to be truncated, len=%d truncated=%v", len(sample.ReqBody), sample.ReqBodyTruncated)
	}
	if sample.ReqBodySHA256 == "" || sample.RespBodySHA256 == "" {
		t.Fatalf("expected body hashes to be populated")
	}
	if !sample.CapturedAt.Equal(raw.CreatedAt) {
		t.Fatalf("captured_at mismatch: %s", sample.CapturedAt)
	}
}

func TestSensitiveSampleFromObservationsMasksOccurrences(t *testing.T) {
	logEntry := core.TrafficLog{
		TenantID:      "tenant-1",
		Method:        "GET",
		Path:          "/users/123",
		CaptureSource: "ebpf",
		CreatedAt:     time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC),
	}
	observations := []sensitiveObservation{
		{Location: endpoint.LocationResponseBody, Name: "email", Value: "alice@example.com", Tags: []string{"EMAIL"}},
	}
	sample := sensitiveSampleFromObservations(logEntry, "https://api.example.com", "/users/{user_id}", "fingerprint", []string{"EMAIL"}, observations, time.Date(2026, 6, 19, 1, 3, 0, 0, time.UTC))

	if sample.SchemaVersion != core.SensitiveSampleSchemaV1 {
		t.Fatalf("unexpected schema: %s", sample.SchemaVersion)
	}
	if len(sample.Occurrences) != 1 {
		t.Fatalf("unexpected occurrences: %#v", sample.Occurrences)
	}
	if sample.Occurrences[0].Sample != redact.Marker {
		t.Fatalf("expected sensitive occurrence sample to be redacted, got %s", sample.Occurrences[0].Sample)
	}
	if sample.SensitiveData[0] != "EMAIL" {
		t.Fatalf("unexpected sensitive tags: %#v", sample.SensitiveData)
	}
}

func TestDetectSensitiveObservationsIncludesResponseBody(t *testing.T) {
	observations := detectSensitiveObservations(core.TrafficLog{
		Path:     "/users/123",
		RespBody: `{"email":"alice@example.com"}`,
	})
	if len(observations) != 1 {
		t.Fatalf("expected one sensitive observation, got %#v", observations)
	}
	if observations[0].Location != endpoint.LocationResponseBody || observations[0].Tags[0] != "EMAIL" {
		t.Fatalf("unexpected observation: %#v", observations[0])
	}
}

func TestMetricBucketStartAndStatusClass(t *testing.T) {
	observed := time.Date(2026, 6, 19, 11, 42, 31, 0, time.FixedZone("IST", 5*60*60+30*60))

	hour := metricBucketStart(observed, core.TrafficMetricGranularityHour)
	if !hour.Equal(time.Date(2026, 6, 19, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected hour bucket: %s", hour)
	}
	day := metricBucketStart(observed, core.TrafficMetricGranularityDay)
	if !day.Equal(time.Date(2026, 6, 19, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected day bucket: %s", day)
	}

	for code, expected := range map[int]string{0: "unknown", 99: "unknown", 200: "2xx", 404: "4xx", 503: "5xx", 600: "unknown"} {
		if got := statusClass(code); got != expected {
			t.Fatalf("statusClass(%d) = %s, want %s", code, got, expected)
		}
	}
}

func TestTrafficMetricEventIDPrefersConversationIDAndFallbackIsStable(t *testing.T) {
	logEntry := core.TrafficLog{
		TenantID:       "tenant-1",
		ProjectID:      "project-1",
		AgentID:        "agent-1",
		ConversationID: "6650f8cb1c5e7c6c1f93a111",
		Method:         "POST",
		URL:            "https://api.example.com/users/123",
		Path:           "/users/123",
		RespStatusCode: 200,
		CreatedAt:      time.Date(2026, 6, 19, 1, 2, 3, 4, time.UTC),
	}
	if got := trafficMetricEventID(logEntry, "fingerprint"); got != "conversation:6650f8cb1c5e7c6c1f93a111" {
		t.Fatalf("unexpected conversation event id: %s", got)
	}

	logEntry.ConversationID = ""
	first := trafficMetricEventID(logEntry, "fingerprint")
	second := trafficMetricEventID(logEntry, "fingerprint")
	if first == "" || first != second || !strings.HasPrefix(first, "log:") {
		t.Fatalf("fallback event id is not stable: first=%s second=%s", first, second)
	}

	logEntry.RespStatusCode = 500
	if changed := trafficMetricEventID(logEntry, "fingerprint"); changed == first {
		t.Fatalf("fallback event id should change when event material changes")
	}
}

func TestTrafficMetricUpdateUsesDimensionsAndCounters(t *testing.T) {
	logEntry := core.TrafficLog{
		TenantID:  "tenant-1",
		ProjectID: "project-1",
		Method:    "post",
	}
	bucketStart := time.Date(2026, 6, 19, 1, 0, 0, 0, time.UTC)
	observed := time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC)
	now := time.Date(2026, 6, 19, 1, 3, 0, 0, time.UTC)

	filter, update := trafficMetricUpdate(logEntry, "https://api.example.com", "/users/{user_id}", "fingerprint", "HIGH", true, true, 503, core.TrafficMetricGranularityHour, bucketStart, observed, now)

	if filter["tenant_id"] != "tenant-1" || filter["project_id"] != "project-1" || filter["endpoint_fingerprint"] != "fingerprint" {
		t.Fatalf("unexpected metric filter identity: %#v", filter)
	}
	if filter["bucket_granularity"] != core.TrafficMetricGranularityHour || filter["bucket_start"] != bucketStart || filter["status_code"] != 503 {
		t.Fatalf("unexpected metric filter dimensions: %#v", filter)
	}

	setOnInsert := update["$setOnInsert"].(bson.M)
	if setOnInsert["schema_version"] != core.TrafficMetricSchemaV1 || setOnInsert["status_class"] != "5xx" || setOnInsert["method"] != "POST" {
		t.Fatalf("unexpected setOnInsert: %#v", setOnInsert)
	}
	inc := update["$inc"].(bson.M)
	if inc["request_count"] != int64(1) || inc["error_count"] != int64(1) || inc["sensitive_count"] != int64(1) {
		t.Fatalf("unexpected increments: %#v", inc)
	}
}

func TestTrafficMetricEventKeyIsBucketScoped(t *testing.T) {
	hour := time.Date(2026, 6, 19, 1, 0, 0, 0, time.UTC)
	key := trafficMetricEventKey("conversation:1", "fingerprint", core.TrafficMetricGranularityHour, hour)
	if key == "" {
		t.Fatalf("expected event key")
	}
	if again := trafficMetricEventKey("conversation:1", "fingerprint", core.TrafficMetricGranularityHour, hour); again != key {
		t.Fatalf("event key should be deterministic")
	}
	if other := trafficMetricEventKey("conversation:1", "fingerprint", core.TrafficMetricGranularityDay, hour); other == key {
		t.Fatalf("event key should include bucket granularity")
	}
}

func TestDeprecatedEndpointRulesAffectRiskReasonsAndTags(t *testing.T) {
	ruleSet, err := lifecyclerules.CompileEndpointRuleSetBytes([]byte(`{
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
		t.Fatalf("compile rules: %v", err)
	}

	findings := endpointRuleFindings(ruleSet, "/api/v1/users/123", "/api/v1/users/{user_id}")
	reasons := reasonsFromRuleFindings(findings)
	tags := tagsFromRuleFindings(findings)

	if len(findings) != 1 || reasons[0] != "deprecated_version:v1" || maxRiskLevel("LOW", riskLevelFromRuleFindings(findings)) != "HIGH" {
		t.Fatalf("unexpected rule findings=%#v reasons=%#v", findings, reasons)
	}
	seenTags := map[string]bool{}
	for _, tag := range tags {
		seenTags[tag] = true
	}
	for _, expected := range []string{"lifecycle:deprecated", "version:v1"} {
		if !seenTags[expected] {
			t.Fatalf("missing tag %s in %#v", expected, tags)
		}
	}
}

func TestAnalyzerRecordedHTTPConversationFixtureProducesSecuritySignals(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "examples", "http.conversation.v1.example.json"))
	if err != nil {
		t.Fatalf("read recorded fixture: %v", err)
	}
	conversation, err := contracts.DecodeAndValidateHTTPConversation(raw)
	if err != nil {
		t.Fatalf("decode recorded fixture: %v", err)
	}

	logEntry := ingest.ConversationToTrafficLog(conversation)
	normalized := endpoint.NormalizePath(logEntry.Path, logEntry.URL)
	if normalized.Pattern != "/api/v1/users" {
		t.Fatalf("unexpected normalized path: %s", normalized.Pattern)
	}
	if logEntry.ConversationID != conversation.ID.OID {
		t.Fatalf("conversation id not mapped into analyzer log: %s", logEntry.ConversationID)
	}

	observations := detectSensitiveObservations(logEntry)
	if tags := tagsFromSensitiveObservations(observations); len(tags) != 1 || tags[0] != "EMAIL" {
		t.Fatalf("expected response email sensitivity from recorded fixture, got observations=%#v tags=%#v", observations, tags)
	}

	ruleSet, err := lifecyclerules.CompileEndpointRuleSetBytes([]byte(`{
		"deprecated": [
			{"name":"fixture-v1","path_regex":"^/api/v1/","reason":"deprecated_version:v1","tags":["lifecycle:deprecated"],"risk_level":"MEDIUM"}
		]
	}`))
	if err != nil {
		t.Fatalf("compile fixture rules: %v", err)
	}
	findings := endpointRuleFindings(ruleSet, logEntry.Path, normalized.Pattern)
	if len(findings) != 1 || findings[0].Reason != "deprecated_version:v1" {
		t.Fatalf("expected fixture lifecycle finding, got %#v", findings)
	}
}
