package db
import(
	"context"
	"karaxys_backend/internal/core"
	"log"
	"strings"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
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
	logEntry.ID = primitive.NewObjectID()
	logEntry.CreatedAt = time.Now()
	_, err := db.Logs.InsertOne(ctx, logEntry)
	if err != nil {
		log.Printf("Failed to save log entry: %v\n", err)
		return err
	}
	return nil
}

func (db *DB) GetInventory(p Pagination) (*PaginatedResponse, error) {
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
	total, err := coll.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, err
	}

	opts := options.Find().
		SetLimit(int64(p.Limit)).
		SetSkip(int64(p.Offset)).
		SetSort(bson.D{{Key: sanitizeSortField(p.SortBy), Value: sanitizeSortOrder(p.SortOrder)}})

	cursor, err := coll.Find(ctx, bson.M{}, opts)
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

	coll := db.Client.Database(db.Name).Collection("scan_results")
	_, err := coll.InsertOne(ctx, scanRes)
	return err
}

func (db *DB) GetScanResults(p Pagination, inventoryID *primitive.ObjectID) (*PaginatedResponse, error) {
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
	if inventoryID != nil {
		filter["inventory_id"] = *inventoryID
	}

	coll := db.Client.Database(db.Name).Collection("scan_results")
	total, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return nil, err
	}

	opts := options.Find().
		SetLimit(int64(p.Limit)).
		SetSkip(int64(p.Offset)).
		SetSort(bson.D{{Key: sanitizeScanResultSortField(p.SortBy), Value: sanitizeSortOrder(p.SortOrder)}})

	cursor, err := coll.Find(ctx, filter, opts)
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