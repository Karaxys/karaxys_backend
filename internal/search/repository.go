package search

import (
	"context"
	"regexp"
	"strings"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const defaultInventorySearchLimit int64 = 100

type InventorySearchFilter struct {
	TenantID   string
	ProjectID  string
	Query      string
	RiskLevels []string
	Tags       []string
	Limit      int64
}

type InventoryRepository interface {
	SearchInventory(ctx context.Context, filter InventorySearchFilter) ([]core.ApiInventory, error)
}

type MongoInventoryRepository struct {
	Collection *mongo.Collection
}

func NewMongoInventoryRepository(collection *mongo.Collection) *MongoInventoryRepository {
	return &MongoInventoryRepository{Collection: collection}
}

func (r *MongoInventoryRepository) SearchInventory(ctx context.Context, filter InventorySearchFilter) ([]core.ApiInventory, error) {
	if r == nil || r.Collection == nil {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > defaultInventorySearchLimit {
		limit = defaultInventorySearchLimit
	}
	cursor, err := r.Collection.Find(ctx, buildInventorySearchFilter(filter), options.Find().
		SetSort(bson.D{{Key: "updated_at", Value: -1}}).
		SetLimit(limit))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var inventory []core.ApiInventory
	if err := cursor.All(ctx, &inventory); err != nil {
		return nil, err
	}
	return inventory, nil
}

func buildInventorySearchFilter(filter InventorySearchFilter) bson.M {
	out := bson.M{}
	if value := strings.TrimSpace(filter.TenantID); value != "" {
		out["tenant_id"] = value
	}
	if value := strings.TrimSpace(filter.ProjectID); value != "" {
		out["project_id"] = value
	}
	if levels := cleanStrings(filter.RiskLevels); len(levels) > 0 {
		out["risk_level"] = bson.M{"$in": levels}
	}
	if tags := cleanStrings(filter.Tags); len(tags) > 0 {
		out["tags"] = bson.M{"$all": tags}
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		regex := bson.M{"$regex": regexp.QuoteMeta(query), "$options": "i"}
		out["$or"] = []bson.M{
			{"method": regex},
			{"host": regex},
			{"base_url": regex},
			{"path_pattern": regex},
			{"original_path": regex},
			{"sensitive_data": regex},
			{"tags": regex},
		}
	}
	return out
}

func cleanStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
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
