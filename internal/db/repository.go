package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/redact"
	"log"
	"strings"
	"time"
)

type Pagination struct {
	Page      int
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	Offset     int         `json:"offset"`
	Limit      int         `json:"limit"`
	TotalPages int         `json:"total_pages"`
}

var ErrScanJobNotCancellable = errors.New("scan job is not cancellable")

func (db *DB) SaveLog(logEntry core.TrafficLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logEntry = redact.TrafficLog(logEntry)
	if ShouldDropTrafficLog(logEntry) {
		return core.ErrTrafficLogDropped
	}
	if logEntry.ID.IsZero() {
		logEntry.ID = primitive.NewObjectID()
	}
	if logEntry.CreatedAt.IsZero() {
		logEntry.CreatedAt = time.Now()
	}
	if strings.TrimSpace(logEntry.ConversationHash) != "" {
		filter := bson.M{"conversation_hash": logEntry.ConversationHash}
		update := bson.M{"$setOnInsert": logEntry}
		result, err := db.Logs.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				return core.ErrTrafficLogDuplicate
			}
			log.Printf("Failed to save log entry: %v\n", err)
			return err
		}
		if result.MatchedCount > 0 {
			return core.ErrTrafficLogDuplicate
		}
		if err := db.PruneTrafficLogs(ctx); err != nil && !errors.Is(err, core.ErrTrafficLogDropped) {
			log.Printf("Failed to prune traffic logs: %v\n", err)
		}
		return nil
	}
	_, err := db.Logs.InsertOne(ctx, logEntry)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return core.ErrTrafficLogDuplicate
		}
		log.Printf("Failed to save log entry: %v\n", err)
		return err
	}
	if err := db.PruneTrafficLogs(ctx); err != nil && !errors.Is(err, core.ErrTrafficLogDropped) {
		log.Printf("Failed to prune traffic logs: %v\n", err)
	}
	return nil
}

func (db *DB) SaveConversation(conversation core.TrafficConversation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conversation = redact.TrafficConversation(conversation)
	if conversation.ID.IsZero() {
		conversation.ID = primitive.NewObjectID()
	}
	if conversation.CreatedAt.IsZero() {
		conversation.CreatedAt = time.Now()
	}
	_, err := db.TrafficConversations.InsertOne(ctx, conversation)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return core.ErrTrafficLogDuplicate
		}
		log.Printf("Failed to save traffic conversation: %v\n", err)
	}
	return err
}

func (db *DB) SaveIngestionLog(logEntry core.IngestionLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if logEntry.ID.IsZero() {
		logEntry.ID = primitive.NewObjectID()
	}
	if logEntry.CreatedAt.IsZero() {
		logEntry.CreatedAt = time.Now()
	}
	_, err := db.IngestionLogs.InsertOne(ctx, logEntry)
	if err != nil {
		log.Printf("Failed to save ingestion log: %v\n", err)
	}
	return err
}

func (db *DB) SaveIngestDeadLetter(deadLetter core.IngestDeadLetter) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadLetter = redact.IngestDeadLetter(deadLetter)
	if deadLetter.ID.IsZero() {
		deadLetter.ID = primitive.NewObjectID()
	}
	if deadLetter.CreatedAt.IsZero() {
		deadLetter.CreatedAt = time.Now()
	}
	_, err := db.IngestDeadLetters.InsertOne(ctx, deadLetter)
	if err != nil {
		log.Printf("Failed to save ingest dead letter: %v\n", err)
	}
	return err
}

func (db *DB) GetTrafficLogByConversationID(ctx context.Context, conversationID string) (core.TrafficLog, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return core.TrafficLog{}, errors.New("conversation id is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	opts := options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}})
	var logEntry core.TrafficLog
	err := db.Logs.FindOne(ctx, bson.M{"conversation_id": conversationID}, opts).Decode(&logEntry)
	return logEntry, err
}

func (db *DB) SaveAuditLog(entry core.AuditLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if entry.ID.IsZero() {
		entry.ID = primitive.NewObjectID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err := db.AuditLogs.InsertOne(ctx, entry)
	if err != nil {
		log.Printf("Failed to save audit log: %v\n", err)
	}
	return err
}

func (db *DB) CreateScanJob(job core.ScanJob) (core.ScanJob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	if job.ID.IsZero() {
		job.ID = primitive.NewObjectID()
	}
	if job.Status == "" {
		job.Status = core.ScanJobStatusQueued
	}
	if job.TimeoutSeconds <= 0 {
		job.TimeoutSeconds = core.DefaultScanTimeoutSeconds
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	_, err := db.ScanJobs.InsertOne(ctx, job)
	return job, err
}

func (db *DB) GetScanJob(id primitive.ObjectID) (*core.ScanJob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var job core.ScanJob
	if err := db.ScanJobs.FindOne(ctx, bson.M{"_id": id}).Decode(&job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (db *DB) ClaimNextScanJob(workerID string) (*core.ScanJob, error) {
	now := time.Now().UTC()
	return db.claimScanJob(workerID, bson.M{
		"status": core.ScanJobStatusQueued,
		"$or": []bson.M{
			{"not_before_at": bson.M{"$exists": false}},
			{"not_before_at": bson.M{"$lte": now}},
		},
	})
}

func (db *DB) ClaimScanJobByID(id primitive.ObjectID, workerID string) (*core.ScanJob, error) {
	now := time.Now().UTC()
	return db.claimScanJob(workerID, bson.M{
		"_id":    id,
		"status": core.ScanJobStatusQueued,
		"$or": []bson.M{
			{"not_before_at": bson.M{"$exists": false}},
			{"not_before_at": bson.M{"$lte": now}},
		},
	})
}

func (db *DB) claimScanJob(workerID string, filter bson.M) (*core.ScanJob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	opts := options.FindOneAndUpdate().
		SetSort(bson.D{{Key: "created_at", Value: 1}}).
		SetReturnDocument(options.After)
	update := bson.M{
		"$set": bson.M{
			"status":     core.ScanJobStatusRunning,
			"worker_id":  workerID,
			"started_at": now,
			"updated_at": now,
			"error":      "",
		},
		"$inc": bson.M{"attempts": 1},
	}

	var job core.ScanJob
	err := db.ScanJobs.FindOneAndUpdate(ctx, filter, update, opts).Decode(&job)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if job.TimeoutSeconds <= 0 {
		job.TimeoutSeconds = core.DefaultScanTimeoutSeconds
	}
	job.DeadlineAt = now.Add(time.Duration(job.TimeoutSeconds) * time.Second)
	_, err = db.ScanJobs.UpdateOne(ctx, bson.M{"_id": job.ID, "status": core.ScanJobStatusRunning}, bson.M{"$set": bson.M{
		"timeout_seconds": job.TimeoutSeconds,
		"deadline_at":     job.DeadlineAt,
		"updated_at":      now,
	}})
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (db *DB) CompleteScanJob(id primitive.ObjectID, resultsCount int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	_, err := db.ScanJobs.UpdateOne(ctx, bson.M{"_id": id, "status": core.ScanJobStatusRunning}, bson.M{"$set": bson.M{
		"status":        core.ScanJobStatusCompleted,
		"results_count": resultsCount,
		"completed_at":  now,
		"updated_at":    now,
		"error":         "",
	}})
	return err
}

func (db *DB) FailScanJob(id primitive.ObjectID, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	_, err := db.ScanJobs.UpdateOne(ctx, bson.M{"_id": id, "status": bson.M{"$in": []string{core.ScanJobStatusQueued, core.ScanJobStatusRunning}}}, bson.M{"$set": bson.M{
		"status":       core.ScanJobStatusFailed,
		"error":        message,
		"completed_at": now,
		"updated_at":   now,
	}})
	return err
}

func (db *DB) RequeueScanJob(id primitive.ObjectID, message string, delay time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	if delay < 0 {
		delay = 0
	}
	_, err := db.ScanJobs.UpdateOne(ctx, bson.M{"_id": id, "status": core.ScanJobStatusRunning}, bson.M{
		"$set": bson.M{
			"status":        core.ScanJobStatusQueued,
			"error":         message,
			"not_before_at": now.Add(delay),
			"updated_at":    now,
		},
		"$unset": bson.M{
			"worker_id":   "",
			"started_at":  "",
			"deadline_at": "",
		},
	})
	return err
}

func (db *DB) TimeoutScanJob(id primitive.ObjectID, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	_, err := db.ScanJobs.UpdateOne(ctx, bson.M{"_id": id, "status": core.ScanJobStatusRunning}, bson.M{"$set": bson.M{
		"status":       core.ScanJobStatusTimedOut,
		"error":        message,
		"completed_at": now,
		"updated_at":   now,
	}})
	return err
}

func (db *DB) CancelScanJob(id primitive.ObjectID, tenantID string) (*core.ScanJob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	filter := bson.M{
		"_id":    id,
		"status": bson.M{"$in": []string{core.ScanJobStatusQueued, core.ScanJobStatusRunning}},
	}
	if strings.TrimSpace(tenantID) != "" {
		filter["tenant_id"] = tenantID
	}
	update := bson.M{"$set": bson.M{
		"status":              core.ScanJobStatusCancelled,
		"cancel_requested_at": now,
		"cancelled_at":        now,
		"completed_at":        now,
		"updated_at":          now,
		"error":               "scan cancelled",
	}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var job core.ScanJob
	err := db.ScanJobs.FindOneAndUpdate(ctx, filter, update, opts).Decode(&job)
	if errors.Is(err, mongo.ErrNoDocuments) {
		existing, getErr := db.GetScanJob(id)
		if getErr != nil {
			return nil, err
		}
		if strings.TrimSpace(tenantID) != "" && existing.TenantID != tenantID {
			return nil, mongo.ErrNoDocuments
		}
		return existing, ErrScanJobNotCancellable
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (db *DB) PruneTrafficLogs(ctx context.Context) error {
	retention := normalizeLogRetention(db.LogRetention)
	if retention.MaxEvents <= 0 {
		return nil
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}).
		SetSkip(retention.MaxEvents).
		SetProjection(bson.M{"_id": 1}).
		SetLimit(1000)

	cursor, err := db.Logs.Find(ctx, bson.M{}, opts)
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
		ids = append(ids, item.ID)
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}

	_, err = db.Logs.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	return err
}

func (db *DB) GetInventory(p Pagination) (*PaginatedResponse, error) {
	return db.getInventory(p, bson.M{})
}

func (db *DB) GetInventoryForAccount(p Pagination, accountID primitive.ObjectID) (*PaginatedResponse, error) {
	if accountID.IsZero() {
		return db.getInventory(p, bson.M{})
	}
	return db.getInventory(p, bson.M{"tenant_id": accountID.Hex()})
}

func (db *DB) getInventory(p Pagination, filter bson.M) (*PaginatedResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if p.Limit < 1 {
		p.Limit = 10
	}
	if p.Limit > 100 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	if p.Offset == 0 && p.Page > 0 {
		p.Offset = (p.Page - 1) * p.Limit
	}
	if p.Page < 1 {
		p.Page = (p.Offset / p.Limit) + 1
	}

	coll := db.Client.Database(db.Name).Collection("api_inventory")
	total, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}

	opts := options.Find().
		SetLimit(int64(p.Limit)).
		SetSkip(int64(p.Offset)).
		SetSort(bson.D{{Key: sanitizeSortField(p.SortBy), Value: sanitizeSortOrder(p.SortOrder)}})

	cursor, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	var results []core.ApiInventory
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	totalPages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		totalPages++
	}
	response := &PaginatedResponse{
		Data:       results,
		Total:      total,
		Page:       p.Page,
		Offset:     p.Offset,
		Limit:      p.Limit,
		TotalPages: totalPages,
	}
	return response, nil
}

func sanitizeSortField(field string) string {
	switch strings.ToLower(field) {
	case "created_at":
		return "created_at"
	case "method":
		return "method"
	case "base_url":
		return "base_url"
	case "path_pattern":
		return "path_pattern"
	default:
		return "updated_at"
	}
}

func sanitizeSortOrder(order string) int {
	if strings.ToLower(order) == "asc" {
		return 1
	}
	return -1
}

func (db *DB) SaveScanResult(scanRes core.ScanResult) (*core.ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scanRes = redact.ScanResult(scanRes)

	if scanRes.ID.IsZero() {
		scanRes.ID = primitive.NewObjectID()
	}
	if scanRes.CreatedAt.IsZero() {
		scanRes.CreatedAt = time.Now().UTC()
	}
	_, err := db.ScanResults.InsertOne(ctx, scanRes)
	if err != nil {
		return nil, err
	}
	return &scanRes, nil
}

func (db *DB) UpsertIssueFromScanResult(scanRes core.ScanResult) (*core.Issue, error) {
	if !scanRes.Vulnerable {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var inventory core.ApiInventory
	endpointFingerprint := ""
	if !scanRes.InventoryID.IsZero() {
		err := db.Client.Database(db.Name).Collection("api_inventory").FindOne(ctx, bson.M{"_id": scanRes.InventoryID}).Decode(&inventory)
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			return nil, err
		}
		endpointFingerprint = inventory.EndpointFingerprint
	}

	now := time.Now().UTC()
	if scanRes.CreatedAt.IsZero() {
		scanRes.CreatedAt = now
	}
	fingerprint := issueFingerprint(scanRes.TenantID, scanRes.ProjectID, scanRes.InventoryID, endpointFingerprint, scanRes.TestType)
	title := issueTitle(scanRes.TestType, inventory)
	evidenceSummary := scanRes.Proof
	if evidenceSummary == "" {
		evidenceSummary = scanRes.Description
	}
	if len(evidenceSummary) > 2048 {
		evidenceSummary = evidenceSummary[:2048]
	}

	setOnInsert := bson.M{
		"_id":               primitive.NewObjectID(),
		"tenant_id":         scanRes.TenantID,
		"project_id":        scanRes.ProjectID,
		"inventory_id":      scanRes.InventoryID,
		"issue_fingerprint": fingerprint,
		"test_type":         scanRes.TestType,
		"status":            core.IssueStatusOpen,
		"first_seen_at":     scanRes.CreatedAt,
		"created_at":        now,
	}
	update := bson.M{
		"$setOnInsert": setOnInsert,
		"$set": bson.M{
			"endpoint_fingerprint": endpointFingerprint,
			"scan_job_id":          scanRes.JobID,
			"scan_result_id":       scanRes.ID,
			"severity":             strings.ToLower(strings.TrimSpace(scanRes.Severity)),
			"title":                title,
			"description":          scanRes.Description,
			"evidence_summary":     evidenceSummary,
			"last_seen_at":         scanRes.CreatedAt,
			"updated_at":           now,
		},
	}
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	var issue core.Issue
	if err := db.Issues.FindOneAndUpdate(ctx, bson.M{"issue_fingerprint": fingerprint}, update, opts).Decode(&issue); err != nil {
		return nil, err
	}
	return &issue, nil
}

func issueFingerprint(tenantID string, projectID string, inventoryID primitive.ObjectID, endpointFingerprint string, testType string) string {
	source := strings.Join([]string{
		strings.TrimSpace(tenantID),
		strings.TrimSpace(projectID),
		inventoryID.Hex(),
		strings.TrimSpace(endpointFingerprint),
		strings.TrimSpace(testType),
	}, "|")
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func issueTitle(testType string, inventory core.ApiInventory) string {
	target := strings.TrimSpace(inventory.PathPattern)
	if target == "" {
		target = strings.TrimSpace(inventory.OriginalPath)
	}
	if target == "" {
		target = "captured endpoint"
	}
	method := strings.TrimSpace(inventory.Method)
	if method != "" {
		target = method + " " + target
	}
	return fmt.Sprintf("%s on %s", strings.TrimSpace(testType), target)
}

func (db *DB) ResolveLatestTrafficSample(inventory core.ApiInventory) (*core.TrafficSample, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{}
	if strings.TrimSpace(inventory.EndpointFingerprint) != "" {
		filter["endpoint_fingerprint"] = inventory.EndpointFingerprint
	} else {
		filter["method"] = inventory.Method
		filter["base_url"] = inventory.BaseURL
		filter["path_pattern"] = inventory.PathPattern
	}
	if strings.TrimSpace(inventory.TenantID) != "" {
		filter["tenant_id"] = inventory.TenantID
	}
	opts := options.FindOne().SetSort(bson.D{{Key: "captured_at", Value: -1}, {Key: "created_at", Value: -1}})
	var sample core.TrafficSample
	err := db.TrafficSamples.FindOne(ctx, filter, opts).Decode(&sample)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sample, nil
}

func ApplyTrafficSampleToInventory(inventory core.ApiInventory, sample *core.TrafficSample) core.ApiInventory {
	if sample == nil {
		return inventory
	}
	if strings.TrimSpace(sample.ReqBody) != "" {
		inventory.SampleReqBody = sample.ReqBody
	}
	if len(sample.ReqHeaders) > 0 {
		inventory.SampleHeaders = sample.ReqHeaders
	}
	if strings.TrimSpace(sample.OriginalPath) != "" {
		inventory.OriginalPath = sample.OriginalPath
	}
	if strings.TrimSpace(sample.BaseURL) != "" {
		inventory.BaseURL = sample.BaseURL
	}
	return inventory
}

func (db *DB) SaveScanProgressEvent(event core.ScanProgressEvent) error {
	if db == nil || db.ScanProgressEvents == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if event.ID.IsZero() {
		event.ID = primitive.NewObjectID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := db.ScanProgressEvents.InsertOne(ctx, event)
	return err
}

func (db *DB) GetScanProgressEvents(jobID primitive.ObjectID, tenantID string) ([]core.ScanProgressEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	filter := bson.M{"job_id": jobID}
	if strings.TrimSpace(tenantID) != "" {
		filter["tenant_id"] = tenantID
	}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}})
	cursor, err := db.ScanProgressEvents.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var events []core.ScanProgressEvent
	if err := cursor.All(ctx, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func (db *DB) GetIssues(p Pagination, tenantID string, status string, severity string, inventoryID *primitive.ObjectID) (*PaginatedResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if p.Limit < 1 {
		p.Limit = 10
	}
	if p.Limit > 100 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	if p.Offset == 0 && p.Page > 0 {
		p.Offset = (p.Page - 1) * p.Limit
	}
	if p.Page < 1 {
		p.Page = (p.Offset / p.Limit) + 1
	}

	filter := bson.M{}
	if strings.TrimSpace(tenantID) != "" {
		filter["tenant_id"] = strings.TrimSpace(tenantID)
	}
	if strings.TrimSpace(status) != "" {
		filter["status"] = strings.TrimSpace(status)
	}
	if strings.TrimSpace(severity) != "" {
		filter["severity"] = strings.ToLower(strings.TrimSpace(severity))
	}
	if inventoryID != nil {
		filter["inventory_id"] = *inventoryID
	}

	total, err := db.Issues.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}
	opts := options.Find().
		SetLimit(int64(p.Limit)).
		SetSkip(int64(p.Offset)).
		SetSort(bson.D{{Key: sanitizeIssueSortField(p.SortBy), Value: sanitizeSortOrder(p.SortOrder)}})
	cursor, err := db.Issues.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var issues []core.Issue
	if err := cursor.All(ctx, &issues); err != nil {
		return nil, err
	}
	totalPages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		totalPages++
	}
	return &PaginatedResponse{
		Data:       issues,
		Total:      total,
		Page:       p.Page,
		Offset:     p.Offset,
		Limit:      p.Limit,
		TotalPages: totalPages,
	}, nil
}

func sanitizeIssueSortField(field string) string {
	switch strings.ToLower(field) {
	case "first_seen_at":
		return "first_seen_at"
	case "last_seen_at":
		return "last_seen_at"
	case "severity":
		return "severity"
	case "status":
		return "status"
	default:
		return "updated_at"
	}
}

func (db *DB) GetScanResults(p Pagination, inventoryID *primitive.ObjectID, jobID *primitive.ObjectID, suiteID *primitive.ObjectID) (*PaginatedResponse, error) {
	return db.getScanResults(p, inventoryID, jobID, suiteID, "")
}

func (db *DB) GetScanResultsForAccount(p Pagination, inventoryID *primitive.ObjectID, jobID *primitive.ObjectID, suiteID *primitive.ObjectID, accountID primitive.ObjectID) (*PaginatedResponse, error) {
	if accountID.IsZero() {
		return db.getScanResults(p, inventoryID, jobID, suiteID, "")
	}
	return db.getScanResults(p, inventoryID, jobID, suiteID, accountID.Hex())
}

func (db *DB) getScanResults(p Pagination, inventoryID *primitive.ObjectID, jobID *primitive.ObjectID, suiteID *primitive.ObjectID, tenantID string) (*PaginatedResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if p.Limit < 1 {
		p.Limit = 10
	}
	if p.Limit > 100 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	if p.Offset == 0 && p.Page > 0 {
		p.Offset = (p.Page - 1) * p.Limit
	}
	if p.Page < 1 {
		p.Page = (p.Offset / p.Limit) + 1
	}

	filter := bson.M{}
	if tenantID != "" {
		filter["tenant_id"] = tenantID
	}
	if inventoryID != nil {
		filter["inventory_id"] = *inventoryID
	}
	if jobID != nil {
		filter["job_id"] = *jobID
	}
	if suiteID != nil {
		filter["suite_id"] = *suiteID
	}

	total, err := db.ScanResults.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}

	opts := options.Find().
		SetLimit(int64(p.Limit)).
		SetSkip(int64(p.Offset)).
		SetSort(bson.D{{Key: sanitizeScanResultSortField(p.SortBy), Value: sanitizeSortOrder(p.SortOrder)}})

	cursor, err := db.ScanResults.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	var results []core.ScanResult
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	totalPages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		totalPages++
	}

	response := &PaginatedResponse{
		Data:       results,
		Total:      total,
		Page:       p.Page,
		Offset:     p.Offset,
		Limit:      p.Limit,
		TotalPages: totalPages,
	}
	return response, nil
}

func (db *DB) GetScanJobs(p Pagination, tenantID string, status string, inventoryID *primitive.ObjectID) (*PaginatedResponse, error) {
	return db.getScanJobs(p, tenantID, status, inventoryID)
}

func (db *DB) GetScanJobsForAccount(p Pagination, accountID primitive.ObjectID, status string, inventoryID *primitive.ObjectID) (*PaginatedResponse, error) {
	if accountID.IsZero() {
		return db.getScanJobs(p, "", status, inventoryID)
	}
	return db.getScanJobs(p, accountID.Hex(), status, inventoryID)
}

func (db *DB) getScanJobs(p Pagination, tenantID string, status string, inventoryID *primitive.ObjectID) (*PaginatedResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if p.Limit < 1 {
		p.Limit = 20
	}
	if p.Limit > 100 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	if p.Offset == 0 && p.Page > 0 {
		p.Offset = (p.Page - 1) * p.Limit
	}
	if p.Page < 1 {
		p.Page = (p.Offset / p.Limit) + 1
	}

	filter := bson.M{}
	if strings.TrimSpace(tenantID) != "" {
		filter["tenant_id"] = strings.TrimSpace(tenantID)
	}
	if strings.TrimSpace(status) != "" {
		filter["status"] = strings.TrimSpace(status)
	}
	if inventoryID != nil {
		filter["inventory_id"] = *inventoryID
	}

	total, err := db.ScanJobs.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}

	sortField := "created_at"
	switch strings.ToLower(p.SortBy) {
	case "updated_at":
		sortField = "updated_at"
	case "status":
		sortField = "status"
	case "test_type":
		sortField = "test_type"
	}
	opts := options.Find().
		SetLimit(int64(p.Limit)).
		SetSkip(int64(p.Offset)).
		SetSort(bson.D{{Key: sortField, Value: sanitizeSortOrder(p.SortOrder)}})

	cursor, err := db.ScanJobs.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var jobs []core.ScanJob
	if err = cursor.All(ctx, &jobs); err != nil {
		return nil, err
	}

	totalPages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		totalPages++
	}
	return &PaginatedResponse{
		Data:       jobs,
		Total:      total,
		Page:       p.Page,
		Offset:     p.Offset,
		Limit:      p.Limit,
		TotalPages: totalPages,
	}, nil
}

// GetScanJobsBySuite returns every job belonging to a suite, oldest first, so a
// caller can aggregate suite-level status and findings. Scoped by tenant when a
// non-empty tenantID is supplied.
func (db *DB) GetScanJobsBySuite(suiteID primitive.ObjectID, tenantID string) ([]core.ScanJob, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"suite_id": suiteID}
	if strings.TrimSpace(tenantID) != "" {
		filter["tenant_id"] = strings.TrimSpace(tenantID)
	}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}})
	cursor, err := db.ScanJobs.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var jobs []core.ScanJob
	if err = cursor.All(ctx, &jobs); err != nil {
		return nil, err
	}
	return jobs, nil
}

func (db *DB) UpdateIssueStatus(id primitive.ObjectID, tenantID string, status string) (*core.Issue, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"_id": id}
	if strings.TrimSpace(tenantID) != "" {
		filter["tenant_id"] = strings.TrimSpace(tenantID)
	}
	update := bson.M{"$set": bson.M{"status": status, "updated_at": time.Now().UTC()}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updated core.Issue
	if err := db.Issues.FindOneAndUpdate(ctx, filter, update, opts).Decode(&updated); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return &updated, nil
}

func sanitizeScanResultSortField(field string) string {
	switch strings.ToLower(field) {
	case "created_at":
		return "created_at"
	case "test_type":
		return "test_type"
	case "severity":
		return "severity"
	case "response_status":
		return "response_status"
	default:
		return "created_at"
	}
}

type DailyIssueCount struct {
	Day      string `json:"day"`
	Critical int64  `json:"critical"`
	High     int64  `json:"high"`
	Medium   int64  `json:"medium"`
	Low      int64  `json:"low"`
}

type TopEndpointSummary struct {
	InventoryID string `json:"inventory_id"`
	Path        string `json:"path"`
	Method      string `json:"method"`
	IssueCount  int64  `json:"issue_count"`
}

type MetricsSummary struct {
	Inventory struct {
		Total           int64 `json:"total"`
		Critical        int64 `json:"critical"`
		High            int64 `json:"high"`
		Medium          int64 `json:"medium"`
		Low             int64 `json:"low"`
		Authenticated   int64 `json:"authenticated"`
		Unauthenticated int64 `json:"unauthenticated"`
	} `json:"inventory"`
	Issues struct {
		Total         int64 `json:"total"`
		Critical      int64 `json:"critical"`
		High          int64 `json:"high"`
		Medium        int64 `json:"medium"`
		Low           int64 `json:"low"`
		Open          int64 `json:"open"`
		AcceptedRisk  int64 `json:"accepted_risk"`
		FalsePositive int64 `json:"false_positive"`
		Fixed         int64 `json:"fixed"`
	} `json:"issues"`
	Scans struct {
		Total     int64 `json:"total"`
		Queued    int64 `json:"queued"`
		Running   int64 `json:"running"`
		Completed int64 `json:"completed"`
		Failed    int64 `json:"failed"`
		Cancelled int64 `json:"cancelled"`
	} `json:"scans"`
	Agents struct {
		Total  int64 `json:"total"`
		Online int64 `json:"online"`
	} `json:"agents"`
	SensitiveData struct {
		PII       int64 `json:"pii"`
		Financial int64 `json:"financial"`
		Secrets   int64 `json:"secrets"`
		Other     int64 `json:"other"`
	} `json:"sensitive_data"`
	DailyIssues  []DailyIssueCount    `json:"daily_issues"`
	TopEndpoints []TopEndpointSummary `json:"top_endpoints"`
}

var (
	piiTags       = []string{"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH", "FULL_NAME", "US_SSN", "USER_ID", "USERNAME", "PERSON_NAME", "STREET_ADDRESS", "ADDRESS", "PASSPORT_NO", "DRIVERS_LICENSE", "CANADIAN_SIN", "FINNISH_PIN", "GERMAN_INSURANCE_ID", "INDIAN_AADHAR", "INDIAN_HEALTH_ID", "US_MEDICARE"}
	financialTags = []string{"CREDIT_CARD", "VISA_CARD", "MASTER_CARD", "IBAN_CODE", "SWIFT_CODE", "INDIAN_PAN"}
	secretTags    = []string{"PASSWORD", "AUTH_TOKEN_BEARER", "JWT_TOKEN", "AWS_KEY"}
)

func (db *DB) GetMetricsSummary(accountID primitive.ObjectID) (*MetricsSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tenantID := accountID.Hex()
	inv := db.Client.Database(db.Name).Collection("api_inventory")

	countColl := func(coll *mongo.Collection, filter bson.M) int64 {
		n, _ := coll.CountDocuments(ctx, filter)
		return n
	}

	var summary MetricsSummary

	// Inventory counts
	summary.Inventory.Total = countColl(inv, bson.M{"tenant_id": tenantID})
	summary.Inventory.Critical = countColl(inv, bson.M{"tenant_id": tenantID, "risk_level": "critical"})
	summary.Inventory.High = countColl(inv, bson.M{"tenant_id": tenantID, "risk_level": "high"})
	summary.Inventory.Medium = countColl(inv, bson.M{"tenant_id": tenantID, "risk_level": "medium"})
	summary.Inventory.Low = countColl(inv, bson.M{"tenant_id": tenantID, "risk_level": "low"})
	summary.Inventory.Authenticated = countColl(inv, bson.M{"tenant_id": tenantID, "auth_observed": true})
	summary.Inventory.Unauthenticated = countColl(inv, bson.M{"tenant_id": tenantID, "auth_observed": bson.M{"$ne": true}})

	// Issues counts
	summary.Issues.Total = countColl(db.Issues, bson.M{"tenant_id": tenantID})
	summary.Issues.Critical = countColl(db.Issues, bson.M{"tenant_id": tenantID, "severity": "critical"})
	summary.Issues.High = countColl(db.Issues, bson.M{"tenant_id": tenantID, "severity": "high"})
	summary.Issues.Medium = countColl(db.Issues, bson.M{"tenant_id": tenantID, "severity": "medium"})
	summary.Issues.Low = countColl(db.Issues, bson.M{"tenant_id": tenantID, "severity": "low"})
	summary.Issues.Open = countColl(db.Issues, bson.M{"tenant_id": tenantID, "status": "open"})
	summary.Issues.AcceptedRisk = countColl(db.Issues, bson.M{"tenant_id": tenantID, "status": "accepted_risk"})
	summary.Issues.FalsePositive = countColl(db.Issues, bson.M{"tenant_id": tenantID, "status": "false_positive"})
	summary.Issues.Fixed = countColl(db.Issues, bson.M{"tenant_id": tenantID, "status": "fixed"})

	// Scan job counts
	summary.Scans.Total = countColl(db.ScanJobs, bson.M{"tenant_id": tenantID})
	summary.Scans.Queued = countColl(db.ScanJobs, bson.M{"tenant_id": tenantID, "status": "queued"})
	summary.Scans.Running = countColl(db.ScanJobs, bson.M{"tenant_id": tenantID, "status": "running"})
	summary.Scans.Completed = countColl(db.ScanJobs, bson.M{"tenant_id": tenantID, "status": "completed"})
	summary.Scans.Failed = countColl(db.ScanJobs, bson.M{"tenant_id": tenantID, "status": bson.M{"$in": []string{"failed", "timed_out"}}})
	summary.Scans.Cancelled = countColl(db.ScanJobs, bson.M{"tenant_id": tenantID, "status": "cancelled"})

	// Agent counts
	onlineThreshold := time.Now().UTC().Add(-5 * time.Minute)
	summary.Agents.Total = countColl(db.Agents, bson.M{"account_id": accountID})
	summary.Agents.Online = countColl(db.Agents, bson.M{
		"account_id":   accountID,
		"status":       "active",
		"last_seen_at": bson.M{"$gte": onlineThreshold},
	})

	// Sensitive data breakdown from inventory
	summary.SensitiveData.PII = countColl(inv, bson.M{"tenant_id": tenantID, "sensitive_data": bson.M{"$in": piiTags}})
	summary.SensitiveData.Financial = countColl(inv, bson.M{"tenant_id": tenantID, "sensitive_data": bson.M{"$in": financialTags}})
	summary.SensitiveData.Secrets = countColl(inv, bson.M{"tenant_id": tenantID, "sensitive_data": bson.M{"$in": secretTags}})
	// "Other" = has any sensitive_data but not in the above three categories
	summary.SensitiveData.Other = countColl(inv, bson.M{
		"tenant_id":      tenantID,
		"sensitive_data": bson.M{"$exists": true, "$ne": []string{}},
	}) - summary.SensitiveData.PII - summary.SensitiveData.Financial - summary.SensitiveData.Secrets
	if summary.SensitiveData.Other < 0 {
		summary.SensitiveData.Other = 0
	}

	// 7-day daily issue trend (group by day + severity)
	weekAgo := time.Now().UTC().AddDate(0, 0, -6).Truncate(24 * time.Hour)
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"tenant_id":     tenantID,
			"first_seen_at": bson.M{"$gte": weekAgo},
		}}},
		{{Key: "$project", Value: bson.M{
			"severity": 1,
			"day": bson.M{"$dateToString": bson.M{
				"format": "%Y-%m-%d",
				"date":   "$first_seen_at",
				"timezone": "UTC",
			}},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id":   bson.M{"day": "$day", "severity": "$severity"},
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "_id.day", Value: 1}}}},
	}
	type aggResult struct {
		ID struct {
			Day      string `bson:"day"`
			Severity string `bson:"severity"`
		} `bson:"_id"`
		Count int64 `bson:"count"`
	}
	cur, err := db.Issues.Aggregate(ctx, pipeline)
	if err == nil {
		defer cur.Close(ctx)
		// Build a map of day → severity counts
		dayMap := map[string]*DailyIssueCount{}
		for cur.Next(ctx) {
			var r aggResult
			if cur.Decode(&r) == nil {
				if _, ok := dayMap[r.ID.Day]; !ok {
					dayMap[r.ID.Day] = &DailyIssueCount{Day: r.ID.Day}
				}
				switch r.ID.Severity {
				case "critical":
					dayMap[r.ID.Day].Critical += r.Count
				case "high":
					dayMap[r.ID.Day].High += r.Count
				case "medium":
					dayMap[r.ID.Day].Medium += r.Count
				case "low":
					dayMap[r.ID.Day].Low += r.Count
				}
			}
		}
		// Fill all 7 days (including zero-count days)
		for i := 0; i < 7; i++ {
			day := weekAgo.AddDate(0, 0, i).Format("2006-01-02")
			if d, ok := dayMap[day]; ok {
				summary.DailyIssues = append(summary.DailyIssues, *d)
			} else {
				summary.DailyIssues = append(summary.DailyIssues, DailyIssueCount{Day: day})
			}
		}
	}
	if summary.DailyIssues == nil {
		summary.DailyIssues = []DailyIssueCount{}
	}

	// Top 5 endpoints by issue count
	topPipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"tenant_id": tenantID}}},
		{{Key: "$group", Value: bson.M{
			"_id":   "$inventory_id",
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "count", Value: -1}}}},
		{{Key: "$limit", Value: 5}},
	}
	type topResult struct {
		InventoryID primitive.ObjectID `bson:"_id"`
		Count       int64              `bson:"count"`
	}
	topCur, err := db.Issues.Aggregate(ctx, topPipeline)
	if err == nil {
		defer topCur.Close(ctx)
		for topCur.Next(ctx) {
			var r topResult
			if topCur.Decode(&r) == nil {
				ep := TopEndpointSummary{InventoryID: r.InventoryID.Hex(), IssueCount: r.Count}
				// Enrich with path/method from inventory
				var invDoc struct {
					Method      string `bson:"method"`
					PathPattern string `bson:"path_pattern"`
				}
				if invErr := inv.FindOne(ctx, bson.M{"_id": r.InventoryID}).Decode(&invDoc); invErr == nil {
					ep.Method = invDoc.Method
					ep.Path = invDoc.PathPattern
				}
				summary.TopEndpoints = append(summary.TopEndpoints, ep)
			}
		}
	}
	if summary.TopEndpoints == nil {
		summary.TopEndpoints = []TopEndpointSummary{}
	}

	return &summary, nil
}
