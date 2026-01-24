package scanner
import(
	"fmt"
	"karaxys_backend/internal/core"
)

func BuildScanConfig(targetBaseURL string, inventory *core.ApiInventory, reqManualToken string, reqMethod string, testType string) (ScanConfig, error) {
	tokenToUse := ""
	switch testType{
	case "BOLA":
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

	return ScanConfig{
		TargetURL:    targetBaseURL,
		Method:       inventory.Method,
		Path:         inventory.OriginalPath,
		Body:         bodyToUse,
		Headers:      flatHeaders,
		TestType:     testType,
		ManualAuth:   tokenToUse,
		AttackMethod: methodToUse,
	}, nil
}