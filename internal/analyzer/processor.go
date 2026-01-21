package analyzer

import(
	"context"
	"log"
	"strings"
	"time"
	"net/url"
	"karaxys_backend/internal/analyzer/cluster"
	"karaxys_backend/internal/analyzer/pii"
	"karaxys_backend/internal/analyzer/schema"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Processor struct{
	InventoryColl *mongo.Collection
	ClusterTrie   *cluster.Trie
}

func NewProcessor(db *mongo.Database) *Processor{
	return &Processor{
		InventoryColl: db.Collection("api_inventory"),
		ClusterTrie:   cluster.NewTrie(),
	}
}

func isStaticResource(path string) bool{
	extensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ico", ".svg", ".map", ".ttf"}
	lowerPath := strings.ToLower(path)
	for _, ext := range extensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

func getBaseURL(fullURL string) string{
	u, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func scanPII(scope string, key string, value string, foundTags *[]string){
	keyLower := strings.ToLower(key)
	for _, rule := range pii.Rules{
		if scope == "HEADER"{
			if rule.Name == "ADDRESS" || rule.Name == "PHONE_NUMBER" || rule.Name == "PASSWORD"{
				continue
			}
		}
		if len(rule.Keywords) > 0 {
			match := false
			for _, kw := range rule.Keywords {
				if strings.Contains(keyLower, kw) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		if rule.Regex.MatchString(value){
			if rule.Verifier != nil{
				matchStr := rule.Regex.FindString(value)
				if rule.Verifier(matchStr){
					*foundTags = append(*foundTags, rule.Name)
				}
			} else {
				*foundTags = append(*foundTags, rule.Name)
			}
		}
	}
}

func (e *Processor) ProcessLog(logEntry core.TrafficLog){
	pathPattern, params := e.ClusterTrie.InsertPath(logEntry.Path)
	reqSchema := schema.Learn(logEntry.ReqBody)
	baseURL := getBaseURL(logEntry.URL)
	detectedPII := []string{}
	if !isStaticResource(logEntry.Path) {
		for k, vals := range logEntry.ReqHeaders{
			for _, v := range vals{
				scanPII("HEADER", k, v, &detectedPII)
			}
		}

		flatReq := utils.FlattenJSON(logEntry.ReqBody)
		for k, v := range flatReq{
			scanPII("BODY", k, v, &detectedPII)
		}
		
		flatResp := utils.FlattenJSON(logEntry.RespBody)
		for k, v := range flatResp{
			scanPII("BODY", k, v, &detectedPII)
		}
		scanPII("BODY","url", logEntry.URL, &detectedPII)
	}

	uniquePII := make(map[string]bool)
	finalPII := []string{}
	for _,tag := range detectedPII{
		if !uniquePII[tag]{
			uniquePII[tag] = true
			finalPII = append(finalPII, tag)
		}
	}

	filter := bson.M{
		"method":       logEntry.Method,
		"path_pattern": pathPattern,
		"base_url":     baseURL,
	}

	update := bson.M{
		"$setOnInsert": bson.M{
			"created_at":    time.Now(),
			"original_path": logEntry.Path,
			"base_url":     baseURL,
		},
		"$set": bson.M{
			"updated_at":       time.Now(),
			"sample_req_body":  logEntry.ReqBody,
			"sample_resp_body": logEntry.RespBody,
			"schema_req":       reqSchema,
		},
		"$addToSet": bson.M{
			"sensitive_data": bson.M{"$each": finalPII},
		},
	}

	for paramKey, paramValue := range params{
		update["$addToSet"].(bson.M)["param_values."+paramKey] = paramValue
	}

	for k, v := range logEntry.ReqHeaders{
		if len(v) > 0 {
			update["$addToSet"].(bson.M)["sample_headers."+k] = v[0]
		}
	}

	opts := options.Update().SetUpsert(true)
	_, err := e.InventoryColl.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil{
		log.Printf("Engine Update Error: %v", err)
	} else {
		piiMsg := ""
		if len(detectedPII) > 0{
			piiMsg = " [PII FOUND]"
		}
		log.Printf("Analyzed Logs: %s -> %s%s", logEntry.Path, pathPattern, piiMsg)
	}
}