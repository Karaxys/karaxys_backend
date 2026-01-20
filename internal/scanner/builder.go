package scanner
import(
	"fmt"
	"karaxys_backend/internal/core"
)

func BuildBOLAConfig(targetBaseURL string, inventory *core.ApiInventory, manualToken string) (ScanConfig, error) {	
	attackerToken := ""
	if manualToken != "" {
		attackerToken = manualToken
	} else {
		authHeaders := inventory.SampleHeaders["Authorization"]
		if len(authHeaders) >= 2 {
			attackerToken = authHeaders[1] 
		}
	}
	if attackerToken == "" {
		return ScanConfig{}, fmt.Errorf("cannot run BOLA: No attacker token found. Please provide one manually or browse with a second user")
	}

	return ScanConfig{
		TargetURL:  targetBaseURL,
		Method:     inventory.Method,
		Path:       inventory.OriginalPath,
		Body:       inventory.SampleReqBody,
		TestType:   "BOLA",
		ManualAuth: attackerToken,
	}, nil
}