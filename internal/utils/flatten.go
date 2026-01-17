package utils
import(
	"encoding/json"
	"fmt"
	"strconv"
)

func FlattenJSON(jsonStr string) map[string]string{
	result := make(map[string]string)
	if jsonStr == "" {
		return result
	}
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil{
		return result
	}
	flattenRecursive("", data, result)
	return result
}

func flattenRecursive(prefix string, value interface{}, result map[string]string){
	switch v := value.(type){
	case map[string]interface{}:
		for k, val := range v {
			newKey := k
			if prefix != "" {
				newKey = prefix + "." + k
			}
			flattenRecursive(newKey, val, result)
		}
	case []interface{}:
		for _, val := range v{
			flattenRecursive(prefix, val, result)
		}
	case float64:
		result[prefix] = strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		result[prefix] = v
	case bool:
		result[prefix] = fmt.Sprintf("%v", v)
	case nil:
		result[prefix] = "null"
	default:
		result[prefix] = fmt.Sprintf("%v", v)
	}
}