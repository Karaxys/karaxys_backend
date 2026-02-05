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
	case "BROKEN_USER_AUTH":
		filename = "test_cases/broken-user-authentication.yaml"
	case "BOLA_PARAMETER_POLLUTION":
		filename = "test_cases/bola-by-parameter-pollution.yaml"
	case "SWAGGER_CHECK": 
		filename = "test_cases/swagger-check.yaml"
	case "JWT_NONE_ALGO":
		filename = "test_cases/jwt-none-algo.yaml"
	default:
		return "", fmt.Errorf("unknown test type")
	}

	content, err := templateFS.ReadFile(filename)
	if err != nil{
		return "", err
	}
	return string(content), nil
}