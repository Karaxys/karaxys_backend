package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"karaxys_backend/internal/analyzer/endpoint"
	"karaxys_backend/internal/analyzer/pii"
	lifecyclerules "karaxys_backend/internal/analyzer/rules"
	"karaxys_backend/internal/analyzer/schema"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/redact"
	"karaxys_backend/internal/utils"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	defaultEndpointSampleLimit = 20
	maxStoredSampleBodyBytes   = 16 * 1024
)

type Processor struct {
	InventoryColl        *mongo.Collection
	ParametersColl       *mongo.Collection
	TrafficSamplesColl   *mongo.Collection
	SensitiveSamplesColl *mongo.Collection
	TrafficMetricsColl   *mongo.Collection
	MetricEventsColl     *mongo.Collection
	EndpointRules        *lifecyclerules.CompiledEndpointRuleSet
	EndpointSampleLimit  int
}

type ProcessorOptions struct {
	EndpointSampleLimit int
	EndpointRules       *lifecyclerules.CompiledEndpointRuleSet
}

type sensitiveObservation struct {
	Location string
	Name     string
	Value    string
	Tags     []string
}

func NewProcessor(db *mongo.Database, options ...ProcessorOptions) *Processor {
	opts := ProcessorOptions{EndpointSampleLimit: defaultEndpointSampleLimit}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.EndpointSampleLimit <= 0 {
		opts.EndpointSampleLimit = defaultEndpointSampleLimit
	}
	ruleSet := opts.EndpointRules
	if ruleSet == nil {
		var err error
		ruleSet, err = lifecyclerules.LoadEndpointRuleSetFromEnv()
		if err != nil {
			log.Printf("Endpoint rules load error: %v; using built-in defaults", err)
			ruleSet, _ = lifecyclerules.CompileEndpointRuleSet(lifecyclerules.DefaultEndpointRuleSet())
		}
	}
	return &Processor{
		InventoryColl:        db.Collection("api_inventory"),
		ParametersColl:       db.Collection("api_parameters"),
		TrafficSamplesColl:   db.Collection("traffic_samples"),
		SensitiveSamplesColl: db.Collection("sensitive_samples"),
		TrafficMetricsColl:   db.Collection("traffic_metrics"),
		MetricEventsColl:     db.Collection("traffic_metric_events"),
		EndpointRules:        ruleSet,
		EndpointSampleLimit:  opts.EndpointSampleLimit,
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
	if u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
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

func tagsForField(scope string, key string, value string) []string {
	tags := []string{}
	scanPII(scope, key, value, &tags)
	return uniqueStrings(tags)
}

func detectSensitiveObservations(logEntry core.TrafficLog) []sensitiveObservation {
	if isStaticResource(logEntry.Path) {
		return nil
	}
	var observations []sensitiveObservation
	for key, values := range logEntry.ReqHeaders {
		for _, value := range values {
			if tags := tagsForField("HEADER", key, value); len(tags) > 0 {
				observations = append(observations, sensitiveObservation{
					Location: endpoint.LocationHeader,
					Name:     key,
					Value:    value,
					Tags:     tags,
				})
			}
		}
	}
	for _, param := range endpoint.QueryParameters(logEntry.URL) {
		if tags := tagsForField("BODY", param.Name, param.Value); len(tags) > 0 {
			observations = append(observations, sensitiveObservation{
				Location: endpoint.LocationQuery,
				Name:     param.Name,
				Value:    param.Value,
				Tags:     tags,
			})
		}
	}
	for _, param := range endpoint.CookieParameters(logEntry.ReqHeaders) {
		if tags := tagsForField("BODY", param.Name, param.Value); len(tags) > 0 {
			observations = append(observations, sensitiveObservation{
				Location: endpoint.LocationCookie,
				Name:     param.Name,
				Value:    param.Value,
				Tags:     tags,
			})
		}
	}
	for key, value := range utils.FlattenJSON(logEntry.ReqBody) {
		if tags := tagsForField("BODY", key, value); len(tags) > 0 {
			observations = append(observations, sensitiveObservation{
				Location: endpoint.LocationRequestBody,
				Name:     key,
				Value:    value,
				Tags:     tags,
			})
		}
	}
	for key, values := range logEntry.RespHeaders {
		for _, value := range values {
			if tags := tagsForField("HEADER", key, value); len(tags) > 0 {
				observations = append(observations, sensitiveObservation{
					Location: "response_header",
					Name:     key,
					Value:    value,
					Tags:     tags,
				})
			}
		}
	}
	for key, value := range utils.FlattenJSON(logEntry.RespBody) {
		if tags := tagsForField("BODY", key, value); len(tags) > 0 {
			observations = append(observations, sensitiveObservation{
				Location: endpoint.LocationResponseBody,
				Name:     key,
				Value:    value,
				Tags:     tags,
			})
		}
	}
	return observations
}

func tagsFromSensitiveObservations(observations []sensitiveObservation) []string {
	var tags []string
	for _, observation := range observations {
		tags = append(tags, observation.Tags...)
	}
	return uniqueStrings(tags)
}

func responseTagsFromSensitiveObservations(observations []sensitiveObservation) []string {
	var tags []string
	for _, observation := range observations {
		if observation.Location == endpoint.LocationResponseBody || observation.Location == "response_header" {
			tags = append(tags, observation.Tags...)
		}
	}
	return uniqueStrings(tags)
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
	normalized := endpoint.NormalizePath(logEntry.Path, logEntry.URL)
	pathPattern := normalized.Pattern
	reqSchema := map[string]string(schema.Learn(logEntry.ReqBody))
	respSchema := map[string]string(schema.Learn(logEntry.RespBody))
	baseURL := getBaseURL(logEntry.URL)
	host := normalizedHost(logEntry.Host, logEntry.URL)
	fingerprint := endpoint.Fingerprint(logEntry.TenantID, logEntry.ProjectID, logEntry.Method, baseURL, pathPattern)
	redactedLogEntry := redact.TrafficLog(logEntry)
	sensitiveObservations := detectSensitiveObservations(logEntry)
	detectedPII := tagsFromSensitiveObservations(sensitiveObservations)
	responsePII := responseTagsFromSensitiveObservations(sensitiveObservations)
	if !isStaticResource(logEntry.Path) {
		detectedPII = append(detectedPII, tagsForField("BODY", "url", logEntry.URL)...)
	}

	finalPII := uniqueStrings(detectedPII)

	ruleFindings := endpointRuleFindings(e.EndpointRules, logEntry.Path, pathPattern)
	calculatedRisk := maxRiskLevel(calculateRiskLevel(finalPII), riskLevelFromRuleFindings(ruleFindings))
	finalResponsePII := uniqueStrings(responsePII)
	authObserved := authObserved(logEntry.ReqHeaders)
	statusCode := responseStatusCode(logEntry)
	riskReasons := uniqueStrings(append(calculateRiskReasons(finalPII, finalResponsePII, authObserved, statusCode, logEntry.Path), reasonsFromRuleFindings(ruleFindings)...))
	tags := uniqueStrings(append(endpointTags(logEntry, authObserved, finalPII, finalResponsePII), tagsFromRuleFindings(ruleFindings)...))
	now := time.Now().UTC()

	filter := bson.M{
		"endpoint_fingerprint": fingerprint,
	}

	setOnInsert := bson.M{
		"schema_version":       core.InventorySchemaV2,
		"endpoint_fingerprint": fingerprint,
		"created_at":           now,
		"first_seen_at":        observedAt(logEntry, now),
		"original_path":        logEntry.Path,
		"method":               strings.ToUpper(strings.TrimSpace(logEntry.Method)),
		"path_pattern":         pathPattern,
		"base_url":             baseURL,
		"host":                 host,
	}
	setFields := bson.M{
		"updated_at":       now,
		"last_seen_at":     observedAt(logEntry, now),
		"sample_req_body":  redactedLogEntry.ReqBody,
		"sample_resp_body": redactedLogEntry.RespBody,
		"schema_req":       reqSchema,
		"schema_resp":      respSchema,
		"header_schema":    headerSchema(logEntry.ReqHeaders),
		"risk_level":       calculatedRisk,
		"risk_reasons":     riskReasons,
		"auth_observed":    authObserved,
	}
	addToSet := bson.M{}
	push := bson.M{}
	update := bson.M{
		"$setOnInsert": setOnInsert,
		"$set":         setFields,
		"$inc":         bson.M{"request_count": 1},
	}
	if logEntry.TenantID != "" {
		setOnInsert["tenant_id"] = logEntry.TenantID
	}
	if logEntry.ProjectID != "" {
		setOnInsert["project_id"] = logEntry.ProjectID
	}
	if logEntry.AgentID != "" {
		setFields["agent_id"] = logEntry.AgentID
	}
	if logEntry.CaptureSource != "" {
		setFields["capture_source"] = logEntry.CaptureSource
	}
	if logEntry.CaptureMode != "" {
		setFields["capture_mode"] = logEntry.CaptureMode
	}
	if strings.TrimSpace(logEntry.Path) != "" {
		push["path_examples"] = cappedPush(logEntry.Path, 10)
	}
	if len(finalPII) > 0 {
		addToSet["sensitive_data"] = bson.M{"$each": finalPII}
	}
	if len(tags) > 0 {
		addToSet["tags"] = bson.M{"$each": tags}
	}
	if statusCode > 0 {
		addToSet["status_codes"] = statusCode
	}
	contentTypes := observedContentTypes(logEntry)
	if len(contentTypes) > 0 {
		addToSet["content_types"] = bson.M{"$each": contentTypes}
	}
	for k, v := range redactedLogEntry.ReqHeaders {
		if len(v) > 0 {
			push["sample_headers."+mongoFieldKey(k)] = cappedPush(v[0], 10)
		}
	}
	observations := parameterObservations(normalized.Parameters, logEntry, redactedLogEntry, reqSchema, respSchema)
	for _, observation := range observations {
		if observation.Location == endpoint.LocationPath {
			push["param_values."+mongoFieldKey(observation.Name)] = cappedPush(redact.Text(observation.Value), 10)
		}
	}
	if len(addToSet) > 0 {
		update["$addToSet"] = addToSet
	}
	if len(push) > 0 {
		update["$push"] = push
	}

	opts := options.Update().SetUpsert(true)
	_, err := e.InventoryColl.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		log.Printf("Engine Update Error: %v", err)
		return
	}
	if err := e.upsertParameters(context.TODO(), logEntry, baseURL, pathPattern, fingerprint, observations); err != nil {
		log.Printf("Parameter Update Error: %v", err)
	}
	if err := e.saveTrafficSample(context.TODO(), logEntry, redactedLogEntry, baseURL, host, pathPattern, fingerprint, finalPII, tags, now); err != nil {
		log.Printf("Traffic Sample Update Error: %v", err)
	}
	if err := e.saveSensitiveSample(context.TODO(), logEntry, baseURL, pathPattern, fingerprint, finalPII, sensitiveObservations, now); err != nil {
		log.Printf("Sensitive Sample Update Error: %v", err)
	}
	if err := e.recordTrafficMetrics(context.TODO(), logEntry, baseURL, pathPattern, fingerprint, calculatedRisk, authObserved, len(finalPII) > 0, statusCode, now); err != nil {
		log.Printf("Traffic Metrics Update Error: %v", err)
	}
	piiMsg := ""
	if len(detectedPII) > 0 {
		piiMsg = " [PII FOUND]"
	}
	log.Printf("Analyzed Logs: %s -> %s%s", logEntry.Path, pathPattern, piiMsg)
}

func (e *Processor) upsertParameters(ctx context.Context, logEntry core.TrafficLog, baseURL string, pathPattern string, fingerprint string, observations []endpoint.ParameterObservation) error {
	if e == nil || e.ParametersColl == nil || len(observations) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for _, observation := range observations {
		if strings.TrimSpace(observation.Name) == "" || strings.TrimSpace(observation.Location) == "" {
			continue
		}
		filter := bson.M{
			"endpoint_fingerprint": fingerprint,
			"location":             observation.Location,
			"name":                 observation.Name,
		}
		setOnInsert := bson.M{
			"created_at":           now,
			"first_seen_at":        observedAt(logEntry, now),
			"endpoint_fingerprint": fingerprint,
			"location":             observation.Location,
			"name":                 observation.Name,
		}
		setFields := bson.M{
			"updated_at":   now,
			"last_seen_at": observedAt(logEntry, now),
			"method":       strings.ToUpper(strings.TrimSpace(logEntry.Method)),
			"base_url":     baseURL,
			"path_pattern": pathPattern,
			"confidence":   1.0,
		}
		if logEntry.TenantID != "" {
			setOnInsert["tenant_id"] = logEntry.TenantID
		}
		if logEntry.ProjectID != "" {
			setOnInsert["project_id"] = logEntry.ProjectID
		}
		addToSet := bson.M{}
		if observation.DataType != "" {
			addToSet["data_types"] = observation.DataType
		}
		sensitiveTags := sensitiveTagsFor(observation.Location, observation.Name, observation.Value)
		if len(sensitiveTags) > 0 {
			addToSet["sensitive_data"] = bson.M{"$each": sensitiveTags}
		}
		update := bson.M{
			"$setOnInsert": setOnInsert,
			"$set":         setFields,
			"$inc":         bson.M{"observed_count": 1},
		}
		if len(addToSet) > 0 {
			update["$addToSet"] = addToSet
		}
		if sample := redactedParameterSample(observation.Value, sensitiveTags); sample != "" {
			update["$push"] = bson.M{"sample_values": cappedPush(sample, 10)}
		}
		if _, err := e.ParametersColl.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Processor) saveTrafficSample(ctx context.Context, logEntry core.TrafficLog, redactedLogEntry core.TrafficLog, baseURL string, host string, pathPattern string, fingerprint string, sensitiveData []string, tags []string, now time.Time) error {
	if e == nil || e.TrafficSamplesColl == nil {
		return nil
	}
	sample := trafficSampleFromLog(logEntry, redactedLogEntry, baseURL, host, pathPattern, fingerprint, sensitiveData, tags, now)
	if _, err := e.TrafficSamplesColl.InsertOne(ctx, sample); err != nil {
		return err
	}
	return pruneEndpointSamples(ctx, e.TrafficSamplesColl, fingerprint, e.EndpointSampleLimit)
}

func (e *Processor) saveSensitiveSample(ctx context.Context, logEntry core.TrafficLog, baseURL string, pathPattern string, fingerprint string, sensitiveData []string, observations []sensitiveObservation, now time.Time) error {
	if e == nil || e.SensitiveSamplesColl == nil || len(sensitiveData) == 0 || len(observations) == 0 {
		return nil
	}
	sample := sensitiveSampleFromObservations(logEntry, baseURL, pathPattern, fingerprint, sensitiveData, observations, now)
	if len(sample.Occurrences) == 0 {
		return nil
	}
	if _, err := e.SensitiveSamplesColl.InsertOne(ctx, sample); err != nil {
		return err
	}
	return pruneEndpointSamples(ctx, e.SensitiveSamplesColl, fingerprint, e.EndpointSampleLimit)
}

func (e *Processor) recordTrafficMetrics(ctx context.Context, logEntry core.TrafficLog, baseURL string, pathPattern string, fingerprint string, riskLevel string, auth bool, hasSensitiveData bool, statusCode int, now time.Time) error {
	if e == nil || e.TrafficMetricsColl == nil || e.MetricEventsColl == nil {
		return nil
	}
	eventID := trafficMetricEventID(logEntry, fingerprint)
	if eventID == "" {
		return nil
	}
	observed := observedAt(logEntry, now)
	for _, granularity := range []string{core.TrafficMetricGranularityHour, core.TrafficMetricGranularityDay} {
		bucketStart := metricBucketStart(observed, granularity)
		eventKey := trafficMetricEventKey(eventID, fingerprint, granularity, bucketStart)
		event := trafficMetricEventFromLog(logEntry, eventID, eventKey, fingerprint, granularity, bucketStart, now)
		if _, err := e.MetricEventsColl.InsertOne(ctx, event); err != nil {
			if mongo.IsDuplicateKeyError(err) {
				continue
			}
			return err
		}

		filter, update := trafficMetricUpdate(logEntry, baseURL, pathPattern, fingerprint, riskLevel, auth, hasSensitiveData, statusCode, granularity, bucketStart, observed, now)
		if _, err := e.TrafficMetricsColl.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true)); err != nil {
			_, _ = e.MetricEventsColl.DeleteOne(ctx, bson.M{"event_key": eventKey})
			return err
		}
	}
	return nil
}

func trafficMetricEventFromLog(logEntry core.TrafficLog, eventID string, eventKey string, fingerprint string, granularity string, bucketStart time.Time, now time.Time) core.TrafficMetricEvent {
	return core.TrafficMetricEvent{
		SchemaVersion:       core.TrafficMetricEventSchemaV1,
		EventKey:            eventKey,
		EventID:             eventID,
		TenantID:            logEntry.TenantID,
		ProjectID:           logEntry.ProjectID,
		EndpointFingerprint: fingerprint,
		BucketGranularity:   granularity,
		BucketStart:         bucketStart,
		CreatedAt:           now,
	}
}

func trafficMetricUpdate(logEntry core.TrafficLog, baseURL string, pathPattern string, fingerprint string, riskLevel string, auth bool, hasSensitiveData bool, statusCode int, granularity string, bucketStart time.Time, observed time.Time, now time.Time) (bson.M, bson.M) {
	tenantID := logEntry.TenantID
	projectID := logEntry.ProjectID
	riskLevel = strings.TrimSpace(riskLevel)
	if riskLevel == "" {
		riskLevel = "LOW"
	}

	filter := bson.M{
		"tenant_id":            tenantID,
		"project_id":           projectID,
		"endpoint_fingerprint": fingerprint,
		"bucket_granularity":   granularity,
		"bucket_start":         bucketStart,
		"status_code":          statusCode,
		"auth_observed":        auth,
		"risk_level":           riskLevel,
	}
	setOnInsert := bson.M{
		"schema_version":       core.TrafficMetricSchemaV1,
		"tenant_id":            tenantID,
		"project_id":           projectID,
		"endpoint_fingerprint": fingerprint,
		"method":               strings.ToUpper(strings.TrimSpace(logEntry.Method)),
		"base_url":             baseURL,
		"path_pattern":         pathPattern,
		"bucket_granularity":   granularity,
		"bucket_start":         bucketStart,
		"status_code":          statusCode,
		"status_class":         statusClass(statusCode),
		"auth_observed":        auth,
		"risk_level":           riskLevel,
		"first_seen_at":        observed,
		"created_at":           now,
	}
	setFields := bson.M{
		"updated_at":   now,
		"last_seen_at": observed,
	}
	inc := bson.M{"request_count": int64(1)}
	if statusCode >= 500 && statusCode <= 599 {
		inc["error_count"] = int64(1)
	}
	if hasSensitiveData {
		inc["sensitive_count"] = int64(1)
	}
	return filter, bson.M{
		"$setOnInsert": setOnInsert,
		"$set":         setFields,
		"$inc":         inc,
	}
}

func trafficSampleFromLog(logEntry core.TrafficLog, redactedLogEntry core.TrafficLog, baseURL string, host string, pathPattern string, fingerprint string, sensitiveData []string, tags []string, now time.Time) core.TrafficSample {
	reqBody, reqTruncated := sampleExcerpt(redactedLogEntry.ReqBody, maxStoredSampleBodyBytes)
	respBody, respTruncated := sampleExcerpt(redactedLogEntry.RespBody, maxStoredSampleBodyBytes)
	return core.TrafficSample{
		SchemaVersion:       core.TrafficSampleSchemaV1,
		TenantID:            logEntry.TenantID,
		ProjectID:           logEntry.ProjectID,
		EndpointFingerprint: fingerprint,
		Method:              strings.ToUpper(strings.TrimSpace(logEntry.Method)),
		BaseURL:             baseURL,
		Host:                host,
		PathPattern:         pathPattern,
		OriginalPath:        logEntry.Path,
		URL:                 redactedLogEntry.URL,
		AgentID:             logEntry.AgentID,
		CaptureSource:       logEntry.CaptureSource,
		CaptureMode:         logEntry.CaptureMode,
		ReqHeaders:          redactedLogEntry.ReqHeaders,
		ReqBody:             reqBody,
		ReqBodySHA256:       sha256Hex(redactedLogEntry.ReqBody),
		ReqBodyTruncated:    reqTruncated,
		RespStatus:          logEntry.RespStatus,
		RespStatusCode:      responseStatusCode(logEntry),
		RespHeaders:         redactedLogEntry.RespHeaders,
		RespBody:            respBody,
		RespBodySHA256:      sha256Hex(redactedLogEntry.RespBody),
		RespBodyTruncated:   respTruncated,
		SensitiveData:       uniqueStrings(sensitiveData),
		Tags:                uniqueStrings(tags),
		CapturedAt:          observedAt(logEntry, now),
		CreatedAt:           now,
	}
}

func sensitiveSampleFromObservations(logEntry core.TrafficLog, baseURL string, pathPattern string, fingerprint string, sensitiveData []string, observations []sensitiveObservation, now time.Time) core.SensitiveSample {
	occurrences := make([]core.SensitiveOccurrence, 0, len(observations))
	for _, observation := range observations {
		if len(observation.Tags) == 0 {
			continue
		}
		occurrences = append(occurrences, core.SensitiveOccurrence{
			Location: observation.Location,
			Name:     observation.Name,
			Tags:     uniqueStrings(observation.Tags),
			Sample:   redactedParameterSample(observation.Value, observation.Tags),
		})
	}
	return core.SensitiveSample{
		SchemaVersion:       core.SensitiveSampleSchemaV1,
		TenantID:            logEntry.TenantID,
		ProjectID:           logEntry.ProjectID,
		EndpointFingerprint: fingerprint,
		Method:              strings.ToUpper(strings.TrimSpace(logEntry.Method)),
		BaseURL:             baseURL,
		PathPattern:         pathPattern,
		OriginalPath:        logEntry.Path,
		AgentID:             logEntry.AgentID,
		CaptureSource:       logEntry.CaptureSource,
		SensitiveData:       uniqueStrings(sensitiveData),
		Occurrences:         occurrences,
		CapturedAt:          observedAt(logEntry, now),
		CreatedAt:           now,
	}
}

func pruneEndpointSamples(ctx context.Context, collection *mongo.Collection, fingerprint string, limit int) error {
	if collection == nil || strings.TrimSpace(fingerprint) == "" || limit <= 0 {
		return nil
	}
	findOptions := options.Find().
		SetSort(bson.D{{Key: "captured_at", Value: -1}, {Key: "_id", Value: -1}}).
		SetSkip(int64(limit)).
		SetProjection(bson.M{"_id": 1})
	cursor, err := collection.Find(ctx, bson.M{"endpoint_fingerprint": fingerprint}, findOptions)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	var ids []primitive.ObjectID
	for cursor.Next(ctx) {
		var item struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&item); err != nil {
			return err
		}
		if !item.ID.IsZero() {
			ids = append(ids, item.ID)
		}
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	return err
}

func parameterObservations(pathParams []endpoint.ParameterObservation, logEntry core.TrafficLog, redactedLogEntry core.TrafficLog, reqSchema map[string]string, respSchema map[string]string) []endpoint.ParameterObservation {
	observations := make([]endpoint.ParameterObservation, 0, len(pathParams)+len(logEntry.ReqHeaders)+len(reqSchema)+len(respSchema))
	observations = append(observations, pathParams...)
	observations = append(observations, endpoint.QueryParameters(logEntry.URL)...)
	observations = append(observations, endpoint.CookieParameters(logEntry.ReqHeaders)...)
	for key, values := range redactedLogEntry.ReqHeaders {
		value := ""
		if len(values) > 0 {
			value = values[0]
		}
		observations = append(observations, endpoint.ParameterObservation{
			Name:     key,
			Location: endpoint.LocationHeader,
			Value:    value,
			DataType: "string",
		})
	}
	for key, valueType := range reqSchema {
		observations = append(observations, endpoint.ParameterObservation{
			Name:     key,
			Location: endpoint.LocationRequestBody,
			DataType: valueType,
		})
	}
	for key, valueType := range respSchema {
		observations = append(observations, endpoint.ParameterObservation{
			Name:     key,
			Location: endpoint.LocationResponseBody,
			DataType: valueType,
		})
	}
	return observations
}

func observedAt(logEntry core.TrafficLog, fallback time.Time) time.Time {
	if logEntry.CreatedAt.IsZero() {
		return fallback
	}
	return logEntry.CreatedAt.UTC()
}

func metricBucketStart(observed time.Time, granularity string) time.Time {
	observed = observed.UTC()
	switch granularity {
	case core.TrafficMetricGranularityDay:
		year, month, day := observed.Date()
		return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	default:
		return observed.Truncate(time.Hour)
	}
}

func trafficMetricEventID(logEntry core.TrafficLog, fingerprint string) string {
	if conversationID := strings.TrimSpace(logEntry.ConversationID); conversationID != "" {
		return "conversation:" + conversationID
	}

	observed := ""
	if !logEntry.CreatedAt.IsZero() {
		observed = logEntry.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	parts := []string{
		logEntry.TenantID,
		logEntry.ProjectID,
		logEntry.AgentID,
		strings.ToUpper(strings.TrimSpace(logEntry.Method)),
		logEntry.URL,
		logEntry.Path,
		logEntry.RespStatus,
		strconv.Itoa(responseStatusCode(logEntry)),
		observed,
		sha256Hex(logEntry.ReqBody),
		sha256Hex(logEntry.RespBody),
		fingerprint,
	}
	return "log:" + sha256Hex(strings.Join(parts, "\x00"))
}

func trafficMetricEventKey(eventID string, fingerprint string, granularity string, bucketStart time.Time) string {
	keyMaterial := strings.Join([]string{
		eventID,
		fingerprint,
		granularity,
		bucketStart.UTC().Format(time.RFC3339Nano),
	}, "\x00")
	return sha256Hex(keyMaterial)
}

func statusClass(statusCode int) string {
	if statusCode < 100 || statusCode > 599 {
		return "unknown"
	}
	return strconv.Itoa(statusCode/100) + "xx"
}

func cappedPush(value string, limit int) bson.M {
	return bson.M{"$each": []string{value}, "$slice": -limit}
}

func mongoFieldKey(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.ReplaceAll(value, "$", "_")
	if value == "" {
		return "_"
	}
	return value
}

func normalizedHost(host string, rawURL string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host != "" {
		return host
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

func responseStatusCode(logEntry core.TrafficLog) int {
	if logEntry.RespStatusCode > 0 {
		return logEntry.RespStatusCode
	}
	fields := strings.Fields(logEntry.RespStatus)
	if len(fields) == 0 {
		return 0
	}
	code, err := strconv.Atoi(fields[0])
	if err != nil || code < 100 || code > 599 {
		return 0
	}
	return code
}

func headerSchema(headers map[string][]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		valueType := "string"
		if len(values) > 1 {
			valueType = "array<string>"
		}
		out[mongoFieldKey(key)] = valueType
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func authObserved(headers map[string][]string) bool {
	for key, values := range headers {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "authorization" || normalized == "cookie" || strings.Contains(normalized, "token") || strings.Contains(normalized, "api-key") {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return true
				}
			}
		}
	}
	return false
}

func observedContentTypes(logEntry core.TrafficLog) []string {
	seen := map[string]bool{}
	var out []string
	for _, headers := range []map[string][]string{logEntry.ReqHeaders, logEntry.RespHeaders} {
		for key, values := range headers {
			if !strings.EqualFold(strings.TrimSpace(key), "Content-Type") {
				continue
			}
			for _, value := range values {
				normalized := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
				if normalized == "" || seen[normalized] {
					continue
				}
				seen[normalized] = true
				out = append(out, normalized)
			}
		}
	}
	return out
}

func calculateRiskReasons(piiTags []string, responsePIITags []string, authObserved bool, statusCode int, requestPath string) []string {
	var reasons []string
	if len(piiTags) > 0 {
		reasons = append(reasons, "sensitive_data_detected")
	}
	if len(responsePIITags) > 0 {
		reasons = append(reasons, "sensitive_data_in_response")
	}
	if !authObserved {
		reasons = append(reasons, "no_auth_observed")
	}
	if statusCode >= 500 {
		reasons = append(reasons, "server_error_observed")
	}
	lowerPath := strings.ToLower(requestPath)
	for _, keyword := range []string{"admin", "debug", "swagger", "openapi", "internal"} {
		if strings.Contains(lowerPath, keyword) {
			reasons = append(reasons, "keyword:"+keyword)
		}
	}
	return uniqueStrings(reasons)
}

func endpointTags(logEntry core.TrafficLog, auth bool, piiTags []string, responsePIITags []string) []string {
	tags := []string{}
	if logEntry.CaptureSource != "" {
		tags = append(tags, "capture_source:"+logEntry.CaptureSource)
	}
	if auth {
		tags = append(tags, "auth:observed")
	} else {
		tags = append(tags, "auth:not_observed")
	}
	if len(piiTags) > 0 {
		tags = append(tags, "sensitive_data:observed")
	}
	if len(responsePIITags) > 0 {
		tags = append(tags, "sensitive_data:response")
	}
	lowerPath := strings.ToLower(logEntry.Path)
	for _, keyword := range []string{"admin", "debug", "swagger", "openapi", "internal"} {
		if strings.Contains(lowerPath, keyword) {
			tags = append(tags, "keyword:"+keyword)
		}
	}
	return uniqueStrings(tags)
}

func endpointRuleFindings(ruleSet *lifecyclerules.CompiledEndpointRuleSet, path string, pathPattern string) []lifecyclerules.Finding {
	if ruleSet == nil {
		return nil
	}
	return ruleSet.Evaluate(path, pathPattern)
}

func reasonsFromRuleFindings(findings []lifecyclerules.Finding) []string {
	var reasons []string
	for _, finding := range findings {
		if strings.TrimSpace(finding.Reason) != "" {
			reasons = append(reasons, finding.Reason)
		}
	}
	return uniqueStrings(reasons)
}

func tagsFromRuleFindings(findings []lifecyclerules.Finding) []string {
	var tags []string
	for _, finding := range findings {
		tags = append(tags, finding.Tags...)
	}
	return uniqueStrings(tags)
}

func riskLevelFromRuleFindings(findings []lifecyclerules.Finding) string {
	riskLevel := ""
	for _, finding := range findings {
		riskLevel = maxRiskLevel(riskLevel, finding.RiskLevel)
	}
	return riskLevel
}

func maxRiskLevel(left string, right string) string {
	if riskRank(right) > riskRank(left) {
		return strings.ToUpper(strings.TrimSpace(right))
	}
	if normalized := strings.ToUpper(strings.TrimSpace(left)); riskRank(normalized) > 0 {
		return normalized
	}
	return "LOW"
}

func riskRank(value string) int {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 0
	}
}

func sensitiveTagsFor(scope string, key string, value string) []string {
	tags := []string{}
	scanPII(strings.ToUpper(scope), key, value, &tags)
	return uniqueStrings(tags)
}

func redactedParameterSample(value string, sensitiveTags []string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if len(sensitiveTags) > 0 {
		return redact.Marker
	}
	return redact.Text(value)
}

func sampleExcerpt(value string, limit int) (string, bool) {
	if value == "" || limit <= 0 {
		return "", false
	}
	if len(value) <= limit {
		return value, false
	}
	return value[:limit], true
}

func sha256Hex(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
