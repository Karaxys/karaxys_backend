package scanplan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"karaxys_backend/internal/core"
	"strings"
)

const (
	testBOLA                   = "BOLA"
	testBOLAParameterPollution = "BOLA_PARAMETER_POLLUTION"
	testBFLA                   = "BFLA"
	testBrokenUserAuth         = "BROKEN_USER_AUTH"
	testSwaggerCheck           = "SWAGGER_CHECK"
	testJWTNoneAlgo            = "JWT_NONE_ALGO"
	testJWTInvalidSignature    = "JWT_INVALID_SIGNATURE"
	testOpenRedirect           = "OPEN_REDIRECT"
	testExposedMetrics         = "EXPOSED_METRICS"
)

func BuildScanConfig(targetBaseURL string, inventory *core.ApiInventory, reqManualToken string, reqMethod string, testType string) (core.ScanConfig, error) {
	tokenToUse, err := resolveAuthToken(testType, inventory, reqManualToken)
	if err != nil {
		return core.ScanConfig{}, err
	}

	methodToUse := resolveMethod(testType, inventory.Method, reqMethod)
	targetPath := resolvePath(testType, inventory.OriginalPath, methodToUse)
	bodyToUse := resolveBody(testType, methodToUse, inventory.SampleReqBody)
	flatHeaders := flattenHeaders(inventory.SampleHeaders)

	pollutedBody := ""
	if testType == testBOLAParameterPollution {
		pollutedBody, err = buildPollutedBody(inventory.SampleReqBody)
		if err != nil {
			return core.ScanConfig{}, err
		}
	}
	if testType == testOpenRedirect {
		targetPath = applyOpenRedirect(targetPath)
	}

	return core.ScanConfig{
		TargetURL:    targetBaseURL,
		Method:       inventory.Method,
		Path:         targetPath,
		Body:         bodyToUse,
		PollutedBody: pollutedBody,
		Headers:      flatHeaders,
		TestType:     testType,
		ManualAuth:   tokenToUse,
		AttackMethod: methodToUse,
	}, nil
}

func splitAuthHeader(originalAuthHeader string) (string, string) {
	parts := strings.Split(originalAuthHeader, " ")
	if len(parts) == 2 {
		return parts[0] + " ", parts[1]
	}
	return "", originalAuthHeader
}

func forgeNoneToken(originalAuthHeader string) (string, error) {
	prefix, token := splitAuthHeader(originalAuthHeader)
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 {
		return "", fmt.Errorf("invalid jwt format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode header: %v", err)
	}
	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return "", fmt.Errorf("failed to parse header json")
	}
	headerMap["alg"] = "none"
	headerMap["typ"] = "JWT"

	newHeaderBytes, _ := json.Marshal(headerMap)
	newHeaderStr := base64.RawURLEncoding.EncodeToString(newHeaderBytes)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode payload: %v", err)
	}
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return "", fmt.Errorf("failed to parse payload json")
	}
	newPayloadBytes, _ := json.Marshal(payloadMap)
	newPayloadStr := base64.RawURLEncoding.EncodeToString(newPayloadBytes)
	forgedToken := fmt.Sprintf("%s%s.%s.", prefix, newHeaderStr, newPayloadStr)
	return forgedToken, nil
}

func tamperSignature(originalAuthHeader string) (string, error) {
	prefix, token := splitAuthHeader(originalAuthHeader)
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 {
		return "", fmt.Errorf("invalid jwt format")
	}
	sig := jwtParts[2]
	if len(sig) == 0 {
		return "", fmt.Errorf("signature empty")
	}
	lastChar := sig[len(sig)-1]
	newChar := lastChar + 1
	newSig := sig[:len(sig)-1] + string(newChar)
	return fmt.Sprintf("%s%s.%s.%s", prefix, jwtParts[0], jwtParts[1], newSig), nil
}

func resolveAuthToken(testType string, inventory *core.ApiInventory, reqManualToken string) (string, error) {
	switch testType {
	case testBOLA, testBOLAParameterPollution:
		token := pickToken(reqManualToken, inventory, 1)
		if token == "" {
			return "", fmt.Errorf("BOLA requires an attacker token")
		}
		return token, nil
	case testBrokenUserAuth:
		return "", nil
	case testSwaggerCheck, testOpenRedirect, testExposedMetrics:
		return pickToken(reqManualToken, inventory, 0), nil
	case testJWTNoneAlgo:
		validToken := pickToken(reqManualToken, inventory, 0)
		if validToken == "" {
			return "", fmt.Errorf("JWT_NONE_ALGO requires a valid token to manipulate")
		}
		forged, err := forgeNoneToken(validToken)
		if err != nil {
			return "", fmt.Errorf("failed to forge token: %v", err)
		}
		return forged, nil
	case testJWTInvalidSignature:
		validToken := pickToken(reqManualToken, inventory, 0)
		if validToken == "" {
			return "", fmt.Errorf("JWT_INVALID_SIGNATURE requires a valid token")
		}
		forged, err := tamperSignature(validToken)
		if err != nil {
			return "", err
		}
		return forged, nil
	default:
		return pickToken(reqManualToken, inventory, 0), nil
	}
}

func pickToken(reqManualToken string, inventory *core.ApiInventory, index int) string {
	if reqManualToken != "" {
		return reqManualToken
	}
	authHeaders := inventory.SampleHeaders["Authorization"]
	if index >= 0 && index < len(authHeaders) {
		return authHeaders[index]
	}
	return ""
}

func resolveMethod(testType string, originalMethod string, reqMethod string) string {
	if testType == testBFLA && reqMethod != "" {
		return reqMethod
	}
	if testType == testSwaggerCheck || testType == testExposedMetrics {
		return "GET"
	}
	return originalMethod
}

func resolvePath(testType string, originalPath string, methodToUse string) string {
	if testType == testSwaggerCheck || testType == testExposedMetrics {
		return ""
	}
	if testType == testBFLA && methodToUse == "DELETE" {
		return ensureTrailingID(originalPath)
	}
	return originalPath
}

func resolveBody(testType string, methodToUse string, sampleBody string) string {
	if testType == testSwaggerCheck || testType == testExposedMetrics {
		return ""
	}

	isDestructive := methodToUse == "PUT" || methodToUse == "PATCH" || methodToUse == "POST"
	if isDestructive && (sampleBody == "" || sampleBody == "{}") {
		return `{"UserId":1}`
	}
	return sampleBody
}

func ensureTrailingID(targetPath string) string {
	if strings.HasSuffix(targetPath, "1") || strings.HasSuffix(targetPath, "0") {
		return targetPath
	}
	if !strings.HasSuffix(targetPath, "/") {
		targetPath += "/"
	}
	return targetPath + "1"
}

func flattenHeaders(headers map[string][]string) map[string]string {
	flatHeaders := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			flatHeaders[k] = v[0]
		}
	}
	return flatHeaders
}

func buildPollutedBody(originalBody string) (string, error) {
	var targetParam string
	var attackerValue string
	var victimValue string
	var bodyMap map[string]interface{}
	if err := json.Unmarshal([]byte(originalBody), &bodyMap); err == nil {
		for key, val := range bodyMap {
			lowerKey := strings.ToLower(key)
			isInteresting := strings.HasSuffix(lowerKey, "id") ||
				strings.HasSuffix(lowerKey, "uuid") ||
				strings.HasSuffix(lowerKey, "ref") ||
				strings.HasSuffix(lowerKey, "token") ||
				strings.Contains(lowerKey, "user") ||
				strings.Contains(lowerKey, "account")

			if isInteresting {
				targetParam = key
				attackerValue = fmt.Sprintf("%v", val)
				if attackerValue == "1" {
					victimValue = "2"
				} else {
					victimValue = "1"
				}
				break
			}
		}
	}

	if targetParam == "" {
		return "", fmt.Errorf("BOLA_PARAMETER_POLLUTION failed: no pollutable parameter found in body")
	}

	oldPairStr := fmt.Sprintf("\"%s\":\"%s\"", targetParam, attackerValue)
	oldPairInt := fmt.Sprintf("\"%s\":%s", targetParam, attackerValue)

	injection := fmt.Sprintf(", \"%s\":%s", targetParam, victimValue)
	if strings.Contains(originalBody, oldPairStr) {
		injection = fmt.Sprintf(", \"%s\":\"%s\"", targetParam, victimValue)
		return strings.Replace(originalBody, oldPairStr, oldPairStr+injection, 1), nil
	}
	if strings.Contains(originalBody, oldPairInt) {
		return strings.Replace(originalBody, oldPairInt, oldPairInt+injection, 1), nil
	}

	trimmed := strings.TrimSuffix(strings.TrimSpace(originalBody), "}")
	return fmt.Sprintf("%s, \"%s\":\"%s\"}", trimmed, targetParam, victimValue), nil
}

func applyOpenRedirect(originalPath string) string {
	separator := "?"
	if strings.Contains(originalPath, "?") {
		separator = "&"
	}
	return originalPath + separator + "redirect=https://evil.example"
}
