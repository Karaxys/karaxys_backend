package scanner
import(
	"fmt"
	"strings"
	"encoding/json"
	"karaxys_backend/internal/core"
)

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
	bodyToUse := inventory.SampleReqBody
	isDestructive := methodToUse == "PUT" || methodToUse == "PATCH" || methodToUse == "POST"
	if isDestructive && (bodyToUse == "" || bodyToUse == "{}") {
		bodyToUse = `{"UserId":1}` 
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

	return ScanConfig{
		TargetURL:    targetBaseURL,
		Method:       inventory.Method,
		Path:         inventory.OriginalPath,
		Body:         bodyToUse,
		PollutedBody: pollutedBody,
		Headers:      flatHeaders,
		TestType:     testType,
		ManualAuth:   tokenToUse,
		AttackMethod: methodToUse,
	}, nil
}