package analytics

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func TestBuildTrafficMetricFilter(t *testing.T) {
	from := time.Date(2026, 6, 19, 1, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 19, 2, 0, 0, 0, time.UTC)
	filter := buildTrafficMetricFilter(TrafficMetricFilter{
		TenantID:            "tenant-1",
		ProjectID:           "project-1",
		EndpointFingerprint: "fp",
		BucketGranularity:   "hour",
		From:                from,
		To:                  to,
	})

	if filter["tenant_id"] != "tenant-1" || filter["project_id"] != "project-1" || filter["endpoint_fingerprint"] != "fp" {
		t.Fatalf("unexpected identity filter: %#v", filter)
	}
	rangeFilter := filter["bucket_start"].(bson.M)
	if rangeFilter["$gte"] != from || rangeFilter["$lte"] != to {
		t.Fatalf("unexpected bucket range: %#v", rangeFilter)
	}
}
