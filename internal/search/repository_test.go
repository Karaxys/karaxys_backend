package search

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestBuildInventorySearchFilterEscapesQueryAndScopesAccount(t *testing.T) {
	filter := buildInventorySearchFilter(InventorySearchFilter{
		TenantID:   "tenant-1",
		Query:      "/admin/.*",
		RiskLevels: []string{"HIGH", "HIGH", "CRITICAL"},
		Tags:       []string{"lifecycle:deprecated", "auth:not_observed"},
	})

	if filter["tenant_id"] != "tenant-1" {
		t.Fatalf("tenant filter missing: %#v", filter)
	}
	riskLevels := filter["risk_level"].(bson.M)["$in"].([]string)
	if len(riskLevels) != 2 {
		t.Fatalf("risk levels should be deduplicated: %#v", riskLevels)
	}
	orFilters := filter["$or"].([]bson.M)
	if len(orFilters) == 0 {
		t.Fatalf("expected search OR filters")
	}
	firstRegex := orFilters[0]["method"].(bson.M)
	if firstRegex["$regex"] != `/admin/\.\*` {
		t.Fatalf("query was not escaped: %#v", firstRegex)
	}
}
