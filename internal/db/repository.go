package db

import (
	"context"
	"errors"
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
	_, err := db.Logs.InsertOne(ctx, logEntry)
	if err != nil {
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
	err := db.ScanJobs.FindOneAndUpdate(ctx, bson.M{"status": core.ScanJobStatusQueued}, update, opts).Decode(&job)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (db *DB) CompleteScanJob(id primitive.ObjectID, resultsCount int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	_, err := db.ScanJobs.UpdateByID(ctx, id, bson.M{"$set": bson.M{
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
	_, err := db.ScanJobs.UpdateByID(ctx, id, bson.M{"$set": bson.M{
		"status":       core.ScanJobStatusFailed,
		"error":        message,
		"completed_at": now,
		"updated_at":   now,
	}})
	return err
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

func (db *DB) SaveScanResult(scanRes core.ScanResult) error {
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
	return err
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
