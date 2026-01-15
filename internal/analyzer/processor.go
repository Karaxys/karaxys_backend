package analyzer

import(
	"context"
	"log"
	"strings"
	"time"
	"vuln_scanner/internal/analyzer/cluster"
	"vuln_scanner/internal/analyzer/pii"
	"vuln_scanner/internal/analyzer/schema"
	"vuln_scanner/internal/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Engine struct{
	InventoryColl *mongo.Collection
	ClusterTrie   *cluster.Trie
}

func NewProcessor(db *mongo.Database) *Engine{
	return &Engine{
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

func (e *Engine) ProcessLog(logEntry core.TrafficLog){
	pathPattern := e.ClusterTrie.InsertPath(logEntry.Path)
	reqSchema := schema.Learn(logEntry.ReqBody)
	detectedPII := []string{}
	if !isStaticResource(logEntry.Path) {
		fullContent := logEntry.ReqBody + logEntry.RespBody + logEntry.URL
		fullContentLower := strings.ToLower(fullContent)

		for _, rule := range pii.Rules{
			if len(rule.Keywords) > 0 {
				foundKeyword := false
				for _, kw := range rule.Keywords {
					if strings.Contains(fullContentLower, kw) {
						foundKeyword = true
						break
					}
				}
				if !foundKeyword {
					continue
				}
			}

			if rule.Regex.MatchString(fullContent){
				if rule.Verifier != nil {
					match := rule.Regex.FindString(fullContent)
					if rule.Verifier(match) {
						detectedPII = append(detectedPII, rule.Name)
					}
				} else {
					detectedPII = append(detectedPII, rule.Name)
				}
			}
		}
	}

	filter := bson.M{
		"method":       logEntry.Method,
		"path_pattern": pathPattern,
	}

	update := bson.M{
		"$setOnInsert": bson.M{
			"created_at":    time.Now(),
			"original_path": logEntry.Path,
		},
		"$set": bson.M{
			"updated_at":       time.Now(),
			"sample_req_body":  logEntry.ReqBody,
			"sample_resp_body": logEntry.RespBody,
			"schema_req":       reqSchema,
		},
		"$addToSet": bson.M{
			"sensitive_data": bson.M{"$each": detectedPII},
		},
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