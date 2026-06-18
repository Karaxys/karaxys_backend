package analyzer

import (
	"context"
	"karaxys_backend/internal/analyzer/cluster"
	"karaxys_backend/internal/analyzer/pii"
	"karaxys_backend/internal/analyzer/schema"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/redact"
	"karaxys_backend/internal/utils"
	"log"
	"net/url"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Processor struct {
	InventoryColl *mongo.Collection
	ClusterTrie   *cluster.Trie
}

func NewProcessor(db *mongo.Database) *Processor {
	return &Processor{
		InventoryColl: db.Collection("api_inventory"),
		ClusterTrie:   cluster.NewTrie(),
	}
}

func isStaticResource(path string) bool {
	extensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ico", ".svg", ".map", ".ttf"}
	lowerPath := strings.ToLower(path)
	for _, ext := range extensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

func getBaseURL(fullURL string) string {
	u, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func scanPII(scope string, key string, value string, foundTags *[]string) {
	keyLower := strings.ToLower(key)
	for _, rule := range pii.Rules {
		if scope == "HEADER" {
			if rule.Name == "ADDRESS" || rule.Name == "PHONE_NUMBER" || rule.Name == "PASSWORD" {
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
		if rule.Regex.MatchString(value) {
			if rule.Verifier != nil {
				matchStr := rule.Regex.FindString(value)
				if rule.Verifier(matchStr) {
					*foundTags = append(*foundTags, rule.Name)
				}
			} else {
				*foundTags = append(*foundTags, rule.Name)
			}
		}
	}
}

func calculateRiskLevel(piiTags []string) string {
	if len(piiTags) == 0 {
		return "LOW"
	}

	tagWeights := map[string]int{
		// Authentication / secrets
		"PASSWORD":          100,
		"AUTH_TOKEN_BEARER": 100,
		"JWT_TOKEN":         95,
		"AWS_KEY":           100,

		// Payment / banking
		"VISA_CARD":   90,
		"MASTER_CARD": 90,
		"CREDIT_CARD": 85,
		"IBAN_CODE":   75,
		"SWIFT_CODE":  70,

		// Government / national identifiers
		"US_SSN":              90,
		"INDIAN_AADHAR":       90,
		"CANADIAN_SIN":        85,
		"INDIAN_PAN":          75,
		"PASSPORT_NO":         75,
		"DRIVERS_LICENSE":     70,
		"US_MEDICARE":         70,
		"FINNISH_PIN":         80,
		"GERMAN_INSURANCE_ID": 75,
		"INDIAN_HEALTH_ID":    75,

		// Personal profile and contact
		"EMAIL":          35,
		"PHONE_NUMBER":   35,
		"DATE_OF_BIRTH":  45,
		"FULL_NAME":      30,
		"PERSON_NAME":    30,
		"USERNAME":       30,
		"USER_ID":        30,
		"ADDRESS":        40,
		"STREET_ADDRESS": 40,
	}

	authTags := map[string]bool{
		"PASSWORD": true, "AUTH_TOKEN_BEARER": true, "JWT_TOKEN": true, "AWS_KEY": true,
	}
	financialTags := map[string]bool{
		"VISA_CARD": true, "MASTER_CARD": true, "CREDIT_CARD": true, "IBAN_CODE": true, "SWIFT_CODE": true,
	}
	identityTags := map[string]bool{
		"US_SSN": true, "INDIAN_AADHAR": true, "CANADIAN_SIN": true, "INDIAN_PAN": true,
		"PASSPORT_NO": true, "DRIVERS_LICENSE": true, "US_MEDICARE": true, "FINNISH_PIN": true,
		"GERMAN_INSURANCE_ID": true, "INDIAN_HEALTH_ID": true,
	}
	contactTags := map[string]bool{
		"EMAIL": true, "PHONE_NUMBER": true, "DATE_OF_BIRTH": true, "FULL_NAME": true,
		"PERSON_NAME": true, "USERNAME": true, "USER_ID": true, "ADDRESS": true, "STREET_ADDRESS": true,
	}

	tagSet := make(map[string]bool, len(piiTags))
	totalScore := 0
	maxTagWeight := 0
	hasAuth := false
	hasFinancial := false
	hasIdentity := false
	hasContact := false

	for _, tag := range piiTags {
		if tagSet[tag] {
			continue
		}
		tagSet[tag] = true

		weight, exists := tagWeights[tag]
		if !exists {
			weight = 25
		}
		totalScore += weight
		if weight > maxTagWeight {
			maxTagWeight = weight
		}

		if authTags[tag] {
			hasAuth = true
		}
		if financialTags[tag] {
			hasFinancial = true
		}
		if identityTags[tag] {
			hasIdentity = true
		}
		if contactTags[tag] {
			hasContact = true
		}
	}
	if maxTagWeight >= 95 {
		return "CRITICAL"
	}
	if (hasAuth && hasIdentity) || (hasAuth && hasFinancial) || (hasFinancial && hasIdentity) {
		return "CRITICAL"
	}

	if maxTagWeight >= 85 || totalScore >= 170 || (hasIdentity && hasContact) {
		return "HIGH"
	}

	if maxTagWeight >= 40 || totalScore >= 70 || len(tagSet) >= 2 {
		return "MEDIUM"
	}

	return "LOW"
}

func (e *Processor) ProcessLog(logEntry core.TrafficLog) {
	pathPattern, params := e.ClusterTrie.InsertPath(logEntry.Path)
	reqSchema := schema.Learn(logEntry.ReqBody)
	baseURL := getBaseURL(logEntry.URL)
	redactedLogEntry := redact.TrafficLog(logEntry)
	detectedPII := []string{}
	if !isStaticResource(logEntry.Path) {
		for k, vals := range logEntry.ReqHeaders {
			for _, v := range vals {
				scanPII("HEADER", k, v, &detectedPII)
			}
		}

		flatReq := utils.FlattenJSON(logEntry.ReqBody)
		for k, v := range flatReq {
			scanPII("BODY", k, v, &detectedPII)
		}

		flatResp := utils.FlattenJSON(logEntry.RespBody)
		for k, v := range flatResp {
			scanPII("BODY", k, v, &detectedPII)
		}
		scanPII("BODY", "url", logEntry.URL, &detectedPII)
	}

	uniquePII := make(map[string]bool)
	finalPII := []string{}
	for _, tag := range detectedPII {
		if !uniquePII[tag] {
			uniquePII[tag] = true
			finalPII = append(finalPII, tag)
		}
	}

	calculatedRisk := calculateRiskLevel(finalPII)

	filter := bson.M{
		"method":       logEntry.Method,
		"path_pattern": pathPattern,
		"base_url":     baseURL,
	}

	update := bson.M{
		"$setOnInsert": bson.M{
			"created_at":    time.Now(),
			"original_path": logEntry.Path,
			"base_url":      baseURL,
		},
		"$set": bson.M{
			"updated_at":       time.Now(),
			"sample_req_body":  redactedLogEntry.ReqBody,
			"sample_resp_body": redactedLogEntry.RespBody,
			"schema_req":       reqSchema,
			"risk_level":       calculatedRisk,
		},
		"$addToSet": bson.M{
			"sensitive_data": bson.M{"$each": finalPII},
		},
	}

	for paramKey, paramValue := range params {
		update["$addToSet"].(bson.M)["param_values."+paramKey] = paramValue
	}

	for k, v := range redactedLogEntry.ReqHeaders {
		if len(v) > 0 {
			update["$addToSet"].(bson.M)["sample_headers."+k] = v[0]
		}
	}

	opts := options.Update().SetUpsert(true)
	_, err := e.InventoryColl.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		log.Printf("Engine Update Error: %v", err)
	} else {
		piiMsg := ""
		if len(detectedPII) > 0 {
			piiMsg = " [PII FOUND]"
		}
		log.Printf("Analyzed Logs: %s -> %s%s", logEntry.Path, pathPattern, piiMsg)
	}
}
