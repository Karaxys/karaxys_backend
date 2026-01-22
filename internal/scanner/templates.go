package scanner
import(
	"embed"
	"fmt"
)

//go:embed test_cases/*.yaml
var templateFS embed.FS

func GetTemplate(testType string) (string, error){
	var filename string
	switch testType{
	case "BOLA":
		filename = "test_cases/bola-by-changing-auth-token.yaml"
	case "BFLA":
		filename = "test_cases/bfla-by-changing-http-method.yaml"
	default:
		return "", fmt.Errorf("unknown test type")
	}

	content, err := templateFS.ReadFile(filename)
	if err != nil{
		return "", err
	}
	return string(content), nil
}