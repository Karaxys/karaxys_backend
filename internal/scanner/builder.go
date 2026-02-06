package scanner
import(
	"fmt"
	"strings"
	"encoding/json"
	"encoding/base64"
	"net/url"
	"karaxys_backend/internal/core"
)

func forgeNoneToken(originalAuthHeader string) (string, error){
	var token string
	var prefix string
	parts := strings.Split(originalAuthHeader, " ")
	if len(parts) == 2{
		prefix = parts[0] + " "
		token = parts[1]
	}else{
		token = originalAuthHeader
	}
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
	if err != nil{
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
	var token string
	var prefix string
	parts := strings.Split(originalAuthHeader, " ")
	if len(parts) == 2 {
		prefix = parts[0] + " "
		token = parts[1]
	}else{
		token = originalAuthHeader
	}
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 { 
		return "", fmt.Errorf("invalid jwt format") 
	}	
	sig := jwtParts[2]
	if len(sig) > 0 {
		lastChar := sig[len(sig)-1]
		newChar := lastChar + 1
		newSig := sig[:len(sig)-1] + string(newChar)
		return fmt.Sprintf("%s%s.%s.%s", prefix, jwtParts[0], jwtParts[1], newSig), nil
	}
	return "", fmt.Errorf("signature empty")
}

func BuildScanConfig(targetBaseURL string, inventory *core.ApiInventory, reqManualToken string, reqMethod string, testType string) (ScanConfig, error) {
	tokenToUse := ""
	switch testType{
	case "BOLA", "BOLA_PARAMETER_POLLUTION":
		if reqManualToken != "" {
			tokenToUse = reqManualToken
		} else if len(inventory.SampleHeaders["Authorization"]) >= 2{
			tokenToUse = inventory.SampleHeaders["Authorization"][1]
		}
		
		if tokenToUse == "" {
			return ScanConfig{}, fmt.Errorf("BOLA requires an Attacker Token. Provide one in request or capture a second user.")
		}
	case "BROKEN_USER_AUTH":
        tokenToUse = ""
	case "SWAGGER_CHECK":
		if reqManualToken != "" {
			tokenToUse = reqManualToken
		} else if len(inventory.SampleHeaders["Authorization"]) > 0 {
			tokenToUse = inventory.SampleHeaders["Authorization"][0]
		}
	case "JWT_NONE_ALGO":
        validToken := ""
        if reqManualToken != "" {
            validToken = reqManualToken
        } else if len(inventory.SampleHeaders["Authorization"]) > 0 {
            validToken = inventory.SampleHeaders["Authorization"][0]
        }
        if validToken == "" {
            return ScanConfig{}, fmt.Errorf("JWT_NONE_ALGO requires a valid token to manipulate")
        }
        forged, err := forgeNoneToken(validToken)
        if err != nil {
            return ScanConfig{}, fmt.Errorf("failed to forge token: %v", err)
        }
        tokenToUse = forged
	case "JWT_INVALID_SIGNATURE":
        validToken := ""
        if reqManualToken != "" {
            validToken = reqManualToken
        } else if len(inventory.SampleHeaders["Authorization"]) > 0 {
            validToken = inventory.SampleHeaders["Authorization"][0]
        }
        if validToken == "" {
            return ScanConfig{}, fmt.Errorf("JWT_INVALID_SIGNATURE requires a valid token")
        }
        forged, err := tamperSignature(validToken)
        if err != nil {
            return ScanConfig{}, err
        }
        tokenToUse = forged

	default:
		if reqManualToken != "" {
			tokenToUse = reqManualToken
		} else if len(inventory.SampleHeaders["Authorization"]) > 0 {
			tokenToUse = inventory.SampleHeaders["Authorization"][0]
		}
	}

	methodToUse := inventory.Method
	if testType == "BFLA" && reqMethod != "" {
		methodToUse = reqMethod
	}
	if testType == "SWAGGER_CHECK" || testType == "EXPOSED_METRICS" {
		methodToUse = "GET"
	}
	targetPath := inventory.OriginalPath
	if testType == "SWAGGER_CHECK" || testType == "EXPOSED_METRICS" {
		targetPath = ""
	}
	if testType == "BFLA" && methodToUse == "DELETE" {
		if !strings.HasSuffix(targetPath, "1") && !strings.HasSuffix(targetPath, "0"){
			if !strings.HasSuffix(targetPath, "/"){
				targetPath = targetPath + "/"
			}
			targetPath = targetPath + "1"
		}
	}
	bodyToUse := inventory.SampleReqBody
	isDestructive := methodToUse == "PUT" || methodToUse == "PATCH" || methodToUse == "POST"
	if isDestructive && (bodyToUse == "" || bodyToUse == "{}") {
		bodyToUse = `{"UserId":1}` 
	}
	if testType == "SWAGGER_CHECK" || testType == "EXPOSED_METRICS" {
		bodyToUse = ""
	}
	flatHeaders := make(map[string]string)
	for k, v := range inventory.SampleHeaders {
		if len(v) > 0 { flatHeaders[k] = v[0] }
	}

	pollutedBody := ""
	if testType == "BOLA_PARAMETER_POLLUTION" {
		originalBody := inventory.SampleReqBody		
		var targetParam string
		var attackerValue string
		var victimValue string
		var bodyMap map[string]interface{}
		if err := json.Unmarshal([]byte(originalBody), &bodyMap); err == nil{
			for key, val := range bodyMap{
				lowerKey := strings.ToLower(key)
				isInteresting := strings.HasSuffix(lowerKey, "id") || 
								 strings.HasSuffix(lowerKey, "uuid") || 
								 strings.HasSuffix(lowerKey, "ref") ||
								 strings.HasSuffix(lowerKey, "token") ||
                                 strings.Contains(lowerKey, "user") ||
                                 strings.Contains(lowerKey, "account")

				if isInteresting{
					targetParam = key
					attackerValue = fmt.Sprintf("%v", val)
					if attackerValue == "1" {
						victimValue = "2"
					}else{
						victimValue = "1"
					}
					break 
				}
			}
		}

		if targetParam != "" {
			oldPairStr := fmt.Sprintf("\"%s\":\"%s\"", targetParam, attackerValue)
			oldPairInt := fmt.Sprintf("\"%s\":%s", targetParam, attackerValue)
			
			injection := fmt.Sprintf(", \"%s\":%s", targetParam, victimValue)
			if strings.Contains(originalBody, oldPairStr){
				injection = fmt.Sprintf(", \"%s\":\"%s\"", targetParam, victimValue)
				pollutedBody = strings.Replace(originalBody, oldPairStr, oldPairStr+injection, 1)
			}else if strings.Contains(originalBody, oldPairInt){
				pollutedBody = strings.Replace(originalBody, oldPairInt, oldPairInt+injection, 1)
			}else{
				trimmed := strings.TrimSuffix(strings.TrimSpace(originalBody), "}")
				pollutedBody = fmt.Sprintf("%s, \"%s\":\"%s\"}", trimmed, targetParam, victimValue)
			}
		}else{
			return ScanConfig{}, fmt.Errorf("BOLA_PARAMETER_POLLUTION failed: No pollutable parameter (BasketId/UserId) found in body")
		}
	}

	if testType == "OPEN_REDIRECT" {
		u, err := url.Parse(targetPath)
		if err == nil {
			q := u.Query()
			redirectParams := []string{
				"to", "next", "url", "target", "r", "redirect", "redirect_to", 
				"return", "return_to", "dest", "destination", "go", "goto",
				"link", "image_url", "forward", "out", "view",
			}

			foundParam := false
			for paramName, values := range q{
				lowerParam := strings.ToLower(paramName)               
                isTarget := false
                for _, target := range redirectParams {
                    if strings.Contains(lowerParam, target) {
                        isTarget = true
                        break
                    }
                }
                if !isTarget && len(values) > 0 {
                     if strings.HasPrefix(values[0], "/") || strings.HasPrefix(values[0], "http") {
                         isTarget = true
                     }
                }

				if isTarget{
					q.Set(paramName, "http://evil.com")
					foundParam = true
				}
			}

			if foundParam{
				u.RawQuery = q.Encode()
				targetPath = u.String()
			}else{
                var queryParts []string
				for _, p := range redirectParams{
					queryParts = append(queryParts, fmt.Sprintf("%s=http://evil.com", p))
				}
				sprayQuery := strings.Join(queryParts, "&")
				if strings.Contains(targetPath, "?"){
					targetPath += "&" + sprayQuery
				}else{
					targetPath += "?" + sprayQuery
				}
			}
		}
	}

	return ScanConfig{
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