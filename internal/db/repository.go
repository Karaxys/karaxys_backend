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

func (db *DB) GetScanResults(p Pagination, inventoryID *primitive.ObjectID, jobID *primitive.ObjectID) (*PaginatedResponse, error) {
	return db.getScanResults(p, inventoryID, jobID, "")
}

func (db *DB) GetScanResultsForAccount(p Pagination, inventoryID *primitive.ObjectID, jobID *primitive.ObjectID, accountID primitive.ObjectID) (*PaginatedResponse, error) {
	if accountID.IsZero() {
		return db.getScanResults(p, inventoryID, jobID, "")
	}
	return db.getScanResults(p, inventoryID, jobID, accountID.Hex())
}

func (db *DB) getScanResults(p Pagination, inventoryID *primitive.ObjectID, jobID *primitive.ObjectID, tenantID string) (*PaginatedResponse, error) {
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
