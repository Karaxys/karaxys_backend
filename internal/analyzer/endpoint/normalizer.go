package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const (
	LocationPath         = "path"
	LocationQuery        = "query"
	LocationHeader       = "header"
	LocationCookie       = "cookie"
	LocationRequestBody  = "request_body"
	LocationResponseBody = "response_body"
)

type NormalizedPath struct {
	Pattern    string
	Parameters []ParameterObservation
}

type ParameterObservation struct {
	Name     string
	Location string
	Value    string
	DataType string
}

var (
	uuidPattern      = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	objectIDPattern  = regexp.MustCompile(`(?i)^[a-f0-9]{24}$`)
	hashPattern      = regexp.MustCompile(`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$`)
	ulidPattern      = regexp.MustCompile(`(?i)^[0-7][0-9a-hjkmnp-tv-z]{25}$`)
	ksuidPattern     = regexp.MustCompile(`^[0-9A-Za-z]{27}$`)
	cuidPattern      = regexp.MustCompile(`(?i)^c[a-z0-9]{24,}$`)
	versionPattern   = regexp.MustCompile(`(?i)^v\d+(?:\.\d+)?$`)
	mixedIDPattern   = regexp.MustCompile(`(?i)^[a-z][a-z0-9]{1,32}[-_][0-9]{2,}$`)
	tokenLikePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)
)

func NormalizePath(rawPath string, rawURL string) NormalizedPath {
	cleanPath := canonicalPath(rawPath, rawURL)
	if cleanPath == "/" {
		return NormalizedPath{Pattern: "/"}
	}

	segments := strings.Split(strings.Trim(cleanPath, "/"), "/")
	patternSegments := make([]string, 0, len(segments))
	parameters := make([]ParameterObservation, 0)
	seenNames := make(map[string]int)
	lastStatic := ""

	for _, segment := range segments {
		decoded := decodeSegment(segment)
		if decoded == "" {
			continue
		}
		if class, ok := classifySegment(decoded); ok {
			name := uniqueParameterName(parameterName(lastStatic, class), seenNames)
			patternSegments = append(patternSegments, "{"+name+"}")
			parameters = append(parameters, ParameterObservation{
				Name:     name,
				Location: LocationPath,
				Value:    decoded,
				DataType: dataType(decoded),
			})
			continue
		}
		staticSegment := normalizeStaticSegment(decoded)
		patternSegments = append(patternSegments, staticSegment)
		lastStatic = staticSegment
	}

	if len(patternSegments) == 0 {
		return NormalizedPath{Pattern: "/"}
	}
	return NormalizedPath{
		Pattern:    "/" + strings.Join(patternSegments, "/"),
		Parameters: parameters,
	}
}

func QueryParameters(rawURL string) []ParameterObservation {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return nil
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil
	}
	params := make([]ParameterObservation, 0, len(values))
	for key, vals := range values {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		value := ""
		if len(vals) > 0 {
			value = vals[0]
		}
		params = append(params, ParameterObservation{
			Name:     name,
			Location: LocationQuery,
			Value:    value,
			DataType: dataType(value),
		})
	}
	return params
}

func CookieParameters(headers map[string][]string) []ParameterObservation {
	if len(headers) == 0 {
		return nil
	}
	var params []ParameterObservation
	for key, values := range headers {
		if !strings.EqualFold(strings.TrimSpace(key), "Cookie") {
			continue
		}
		for _, headerValue := range values {
			for _, part := range strings.Split(headerValue, ";") {
				name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
				name = strings.TrimSpace(name)
				if !ok || name == "" {
					continue
				}
				params = append(params, ParameterObservation{
					Name:     name,
					Location: LocationCookie,
					Value:    strings.TrimSpace(value),
					DataType: dataType(value),
				})
			}
		}
	}
	return params
}

func Fingerprint(tenantID string, projectID string, method string, baseURL string, pattern string) string {
	parts := []string{
		strings.TrimSpace(tenantID),
		strings.TrimSpace(projectID),
		strings.ToUpper(strings.TrimSpace(method)),
		strings.ToLower(strings.TrimRight(strings.TrimSpace(baseURL), "/")),
		strings.TrimSpace(pattern),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func canonicalPath(rawPath string, rawURL string) string {
	candidate := strings.TrimSpace(rawPath)
	if candidate == "" && rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			candidate = parsed.EscapedPath()
		}
	}
	if candidate == "" {
		return "/"
	}
	if parsed, err := url.Parse(candidate); err == nil && parsed.Path != "" {
		candidate = parsed.EscapedPath()
	}
	if !strings.HasPrefix(candidate, "/") {
		candidate = "/" + candidate
	}
	cleaned := path.Clean(candidate)
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	return cleaned
}

func classifySegment(segment string) (string, bool) {
	if segment == "" || versionPattern.MatchString(segment) {
		return "", false
	}
	if _, err := strconv.ParseInt(segment, 10, 64); err == nil {
		return "id", true
	}
	switch {
	case uuidPattern.MatchString(segment):
		return "uuid", true
	case objectIDPattern.MatchString(segment):
		return "object_id", true
	case ulidPattern.MatchString(segment):
		return "ulid", true
	case hashPattern.MatchString(segment):
		return "hash", true
	case cuidPattern.MatchString(segment):
		return "id", true
	case mixedIDPattern.MatchString(segment):
		return "id", true
	case ksuidPattern.MatchString(segment) && hasDigitAndLetter(segment):
		return "ksuid", true
	case tokenLikePattern.MatchString(segment) && hasDigitAndLetter(segment):
		return "token", true
	default:
		return "", false
	}
}

func parameterName(previousStatic string, class string) string {
	resource := singularizeResource(previousStatic)
	if resource == "" {
		return class
	}
	if class == "id" {
		return resource + "_id"
	}
	return resource + "_" + class
}

func singularizeResource(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, "_-")
	if value == "" || strings.HasPrefix(value, "{") {
		return ""
	}
	value = strings.ReplaceAll(value, "-", "_")
	if strings.HasSuffix(value, "ies") && len(value) > 3 {
		return strings.TrimSuffix(value, "ies") + "y"
	}
	if strings.HasSuffix(value, "ses") && len(value) > 3 {
		return strings.TrimSuffix(value, "es")
	}
	if strings.HasSuffix(value, "s") && len(value) > 1 {
		return strings.TrimSuffix(value, "s")
	}
	return value
}

func uniqueParameterName(name string, seen map[string]int) string {
	if name == "" {
		name = "param"
	}
	seen[name]++
	if seen[name] == 1 {
		return name
	}
	return name + "_" + strconv.Itoa(seen[name])
}

func normalizeStaticSegment(segment string) string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return segment
	}
	return segment
}

func decodeSegment(segment string) string {
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		return segment
	}
	return decoded
}

func dataType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "string"
	}
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return "integer"
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return "float"
	}
	if strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
		return "boolean"
	}
	return "string"
}

func hasDigitAndLetter(value string) bool {
	hasDigit := false
	hasLetter := false
	for _, ch := range value {
		if ch >= '0' && ch <= '9' {
			hasDigit = true
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			hasLetter = true
		}
	}
	return hasDigit && hasLetter
}
