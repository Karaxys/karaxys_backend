package schema

import(
	"encoding/json"
	"reflect"
)

type SchemaDefinition map[string]string

func Learn(jsonBody string) SchemaDefinition{
	if jsonBody == "" {
		return nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &data); err != nil{
		return nil
	}
	schema := make(SchemaDefinition)
	flattenAndLearn("", data, schema)
	return schema
}

func flattenAndLearn(prefix string, data map[string]interface{}, schema SchemaDefinition){
	for k, v := range data{
		keyName := k
		if prefix != "" {
			keyName = prefix + "." + k
		}
		if v == nil{
			continue
		}

		switch val := v.(type){
		case bool:
			schema[keyName] = "boolean"
		case string:
			schema[keyName] = "string"
		case float64:
			if float64(int(val)) == val {
				schema[keyName] = "integer"
			} else {
				schema[keyName] = "float"
			}
		case map[string]interface{}:
			schema[keyName] = "object"
			flattenAndLearn(keyName, val, schema)
		case []interface{}:
			schema[keyName] = "array"
		default:
			schema[keyName] = reflect.TypeOf(v).String()
		}
	}
}