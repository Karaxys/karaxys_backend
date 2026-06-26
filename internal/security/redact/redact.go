package redact

import (
	"regexp"
	"strings"

	"karaxys_backend/internal/core"
)

const Marker = "[REDACTED]"

var (
	authHeaderPattern = regexp.MustCompile(`(?i)(Authorization:\s*)[^\r\n'"]+`)
	cookieLinePattern = regexp.MustCompile(`(?i)((?:Cookie|Set-Cookie):\s*)[^\r\n'"]+`)
	bearerPattern     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	basicPattern      = regexp.MustCompile(`(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}`)
	jwtPattern        = regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	awsAccessPattern  = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)

	jsonSecretPattern = regexp.MustCompile(`(?i)("(?:access_token|refresh_token|id_token|auth_token|token|api_key|apikey|client_secret|secret|password|authorization|cookie)"\s*:\s*")([^"]*)(")`)
	formSecretPattern = regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|auth_token|token|api_key|apikey|client_secret|secret|password)=([^&\s]+)`)
)

func Text(value string) string {
	if value == "" {
		return ""
	}

	redacted := value
	redacted = authHeaderPattern.ReplaceAllString(redacted, "${1}"+Marker)
	redacted = cookieLinePattern.ReplaceAllString(redacted, "${1}"+Marker)
	redacted = jsonSecretPattern.ReplaceAllString(redacted, "${1}"+Marker+"${3}")
	redacted = formSecretPattern.ReplaceAllString(redacted, "${1}="+Marker)
	redacted = bearerPattern.ReplaceAllString(redacted, "Bearer "+Marker)
	redacted = basicPattern.ReplaceAllString(redacted, "Basic "+Marker)
	redacted = awsAccessPattern.ReplaceAllString(redacted, Marker)
	redacted = jwtPattern.ReplaceAllString(redacted, Marker)
	return redacted
}

func Headers(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}

	redacted := make(map[string][]string, len(headers))
	for key, values := range headers {
		copied := make([]string, len(values))
		if isSensitiveHeader(key) {
			for i := range copied {
				copied[i] = Marker
			}
		} else {
			for i, value := range values {
				copied[i] = Text(value)
			}
		}
		redacted[key] = copied
	}
	return redacted
}

func StringHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}

	redacted := make(map[string]string, len(headers))
	for key, value := range headers {
		if isSensitiveHeader(key) {
			redacted[key] = Marker
			continue
		}
		redacted[key] = Text(value)
	}
	return redacted
}

func TrafficLog(logEntry core.TrafficLog) core.TrafficLog {
	logEntry.URL = Text(logEntry.URL)
	logEntry.ReqHeaders = Headers(logEntry.ReqHeaders)
	logEntry.ReqBody = Text(logEntry.ReqBody)
	logEntry.RespHeaders = Headers(logEntry.RespHeaders)
	logEntry.RespBody = Text(logEntry.RespBody)
	return logEntry
}

func TrafficConversation(conversation core.TrafficConversation) core.TrafficConversation {
	conversation.URL = Text(conversation.URL)
	conversation.ReqHeaders = Headers(conversation.ReqHeaders)
	conversation.ReqBody = Text(conversation.ReqBody)
	conversation.RespHeaders = Headers(conversation.RespHeaders)
	conversation.RespBody = Text(conversation.RespBody)
	return conversation
}

func ScanResult(result core.ScanResult) core.ScanResult {
	result.Description = Text(result.Description)
	result.Proof = Text(result.Proof)
	result.ResponseBody = Text(result.ResponseBody)
	result.ResponseHeader = Text(result.ResponseHeader)
	return result
}

func IngestDeadLetter(deadLetter core.IngestDeadLetter) core.IngestDeadLetter {
	deadLetter.Error = Text(deadLetter.Error)
	deadLetter.PayloadExcerpt = Text(deadLetter.PayloadExcerpt)
	return deadLetter
}

func isSensitiveHeader(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	switch normalized {
	case "authorization",
		"proxy-authorization",
		"cookie",
		"set-cookie",
		"x-api-key",
		"api-key",
		"x-auth-token",
		"x-access-token",
		"x-csrf-token",
		"x-xsrf-token",
		"x-amz-security-token":
		return true
	}

	return strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "api-key")
}
