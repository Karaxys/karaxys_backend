package analytics

import (
	"context"
	"strings"
	"time"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const defaultTrafficMetricsLimit int64 = 500

type TrafficMetricFilter struct {
	TenantID            string
	ProjectID           string
	EndpointFingerprint string
	BucketGranularity   string
	From                time.Time
	To                  time.Time
	Limit               int64
}

type TrafficMetricRepository interface {
	ListTrafficMetrics(ctx context.Context, filter TrafficMetricFilter) ([]core.TrafficMetric, error)
}

type MongoTrafficMetricRepository struct {
	Collection *mongo.Collection
}

func NewMongoTrafficMetricRepository(collection *mongo.Collection) *MongoTrafficMetricRepository {
	return &MongoTrafficMetricRepository{Collection: collection}
}

func (r *MongoTrafficMetricRepository) ListTrafficMetrics(ctx context.Context, filter TrafficMetricFilter) ([]core.TrafficMetric, error) {
	if r == nil || r.Collection == nil {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > defaultTrafficMetricsLimit {
		limit = defaultTrafficMetricsLimit
	}
	cursor, err := r.Collection.Find(ctx, buildTrafficMetricFilter(filter), options.Find().
		SetSort(bson.D{{Key: "bucket_start", Value: -1}}).
		SetLimit(limit))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var metrics []core.TrafficMetric
	if err := cursor.All(ctx, &metrics); err != nil {
		return nil, err
	}
	return metrics, nil
}

func buildTrafficMetricFilter(filter TrafficMetricFilter) bson.M {
	out := bson.M{}
	if value := strings.TrimSpace(filter.TenantID); value != "" {
		out["tenant_id"] = value
	}
	if value := strings.TrimSpace(filter.ProjectID); value != "" {
		out["project_id"] = value
	}
	if value := strings.TrimSpace(filter.EndpointFingerprint); value != "" {
		out["endpoint_fingerprint"] = value
	}
	if value := strings.TrimSpace(filter.BucketGranularity); value != "" {
		out["bucket_granularity"] = value
	}
	rangeFilter := bson.M{}
	if !filter.From.IsZero() {
		rangeFilter["$gte"] = filter.From.UTC()
	}
	if !filter.To.IsZero() {
		rangeFilter["$lte"] = filter.To.UTC()
	}
	if len(rangeFilter) > 0 {
		out["bucket_start"] = rangeFilter
	}
	return out
}
