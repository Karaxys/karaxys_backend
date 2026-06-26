package redact

import (
	"strings"
	"testing"

	"karaxys_backend/internal/core"
)

const sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.signaturevalue"

func TestTextRedactsCommonSecrets(t *testing.T) {
	input := `Authorization: Bearer ` + sampleJWT + `
Cookie: session_id=secret-cookie
{"auth_token":"` + sampleJWT + `","api_key":"AKIAIOSFODNN7EXAMPLE","password":"super-secret-value"}
https://api.example.local/users?token=query-secret&safe=1`

	output := Text(input)

	assertNotContains(t, output, sampleJWT)
	assertNotContains(t, output, "secret-cookie")
	assertNotContains(t, output, "AKIAIOSFODNN7EXAMPLE")
	assertNotContains(t, output, "super-secret-value")
	assertNotContains(t, output, "query-secret")
	if !strings.Contains(output, Marker) {
		t.Fatalf("expected marker in output: %s", output)
	}
}

func TestHeadersRedactsSensitiveHeaderValuesAndCopiesMap(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer " + sampleJWT},
		"Cookie":        {"session=secret-cookie"},
		"User-Agent":    {"karaxys-test " + sampleJWT},
	}

	redacted := Headers(headers)

	if redacted["Authorization"][0] != Marker {
		t.Fatalf("authorization header was not fully redacted: %+v", redacted["Authorization"])
	}
	if redacted["Cookie"][0] != Marker {
		t.Fatalf("cookie header was not fully redacted: %+v", redacted["Cookie"])
	}
	assertNotContains(t, redacted["User-Agent"][0], sampleJWT)
	if headers["Authorization"][0] == Marker {
		t.Fatalf("redaction mutated original headers")
	}
}

func TestTrafficLogRedactsStoredFields(t *testing.T) {
	logEntry := core.TrafficLog{
		URL: "https://api.example.local/login?access_token=query-secret",
		ReqHeaders: map[string][]string{
			"Authorization": {"Bearer " + sampleJWT},
		},
		ReqBody:  `{"password":"super-secret-value"}`,
		RespBody: `{"auth_token":"` + sampleJWT + `"}`,
	}

	redacted := TrafficLog(logEntry)

	assertNotContains(t, redacted.URL, "query-secret")
	assertNotContains(t, redacted.ReqBody, "super-secret-value")
	assertNotContains(t, redacted.RespBody, sampleJWT)
	if redacted.ReqHeaders["Authorization"][0] != Marker {
		t.Fatalf("authorization header was not redacted: %+v", redacted.ReqHeaders)
	}
	if strings.Contains(logEntry.RespBody, Marker) {
		t.Fatalf("redaction mutated original log")
	}
}

func TestScanResultRedactsEvidence(t *testing.T) {
	result := core.ScanResult{
		Description:    "matched token=" + sampleJWT,
		Proof:          "curl -H 'Authorization: Bearer " + sampleJWT + "'",
		ResponseHeader: "Set-Cookie: session=secret-cookie",
		ResponseBody:   "HTTP/1.1 200 OK\r\nSet-Cookie: session=secret-cookie\r\n\r\n{\"auth_token\":\"" + sampleJWT + "\"}",
	}

	redacted := ScanResult(result)

	assertNotContains(t, redacted.Description, sampleJWT)
	assertNotContains(t, redacted.Proof, sampleJWT)
	assertNotContains(t, redacted.ResponseHeader, "secret-cookie")
	assertNotContains(t, redacted.ResponseBody, sampleJWT)
	assertNotContains(t, redacted.ResponseBody, "secret-cookie")
}

func assertNotContains(t *testing.T, value string, secret string) {
	t.Helper()
	if strings.Contains(value, secret) {
		t.Fatalf("expected secret %q to be redacted from %q", secret, value)
	}
}
