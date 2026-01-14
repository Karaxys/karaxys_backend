package config
import(
	"fmt"
	"os"
	"github.com/joho/godotenv"
)

type Config struct{
	MongoURI	string
	MongoDBName	string
	ProxyAddr	string
	CertFile	string
	KeyFile	string
}

func LoadConfig() (*Config, error){
	_ = godotenv.Load()
	config := &Config{}
	var missingVars []string
	
	config.MongoURI = getEnv("MONGO_URI", &missingVars)
	config.MongoDBName = getEnv("MONGO_DB_NAME", &missingVars)
	config.ProxyAddr = getEnv("PROXY_ADDR", &missingVars)
	config.CertFile = getEnv("PROXY_CERT_FILE", &missingVars)
	config.KeyFile = getEnv("PROXY_KEY_FILE", &missingVars)
	
	if len(missingVars) > 0{
		return nil, fmt.Errorf("missing required environment variables: %v", missingVars)
	}
	return config, nil
}
func getEnv(key string, missingList *[]string) string{
	value := os.Getenv(key)
	if value == ""{
		*missingList = append(*missingList, key)
	}
	return value
}