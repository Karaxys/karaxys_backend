package db

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"karaxys_backend/internal/core"
)

func TestIssueFingerprintIsDeterministicAndTenantScoped(t *testing.T) {
	inventoryID := primitive.NewObjectID()
	first := issueFingerprint("tenant-a", "project-a", inventoryID, "endpoint-fp", "BOLA")
	second := issueFingerprint("tenant-a", "project-a", inventoryID, "endpoint-fp", "BOLA")
	otherTenant := issueFingerprint("tenant-b", "project-a", inventoryID, "endpoint-fp", "BOLA")

	if first == "" {
		t.Fatal("expected fingerprint")
	}
	if first != second {
		t.Fatalf("fingerprint not deterministic: %s != %s", first, second)
	}
	if first == otherTenant {
		t.Fatal("fingerprint must include tenant scope")
	}
}

func TestIssueTitleUsesMethodAndPathPattern(t *testing.T) {
	title := issueTitle("BROKEN_USER_AUTH", core.ApiInventory{
		Method:      "POST",
		PathPattern: "/users/{id}/login",
	})

	if title != "BROKEN_USER_AUTH on POST /users/{id}/login" {
		t.Fatalf("unexpected title: %s", title)
	}
}

func TestIssueTitleFallsBackToCapturedEndpoint(t *testing.T) {
	title := issueTitle("EXPOSED_METRICS", core.ApiInventory{})

	if title != "EXPOSED_METRICS on captured endpoint" {
		t.Fatalf("unexpected title: %s", title)
	}
}

func TestApplyTrafficSampleToInventoryKeepsInventoryFallbacks(t *testing.T) {
	inventory := core.ApiInventory{
		BaseURL:       "https://api.example.com",
		OriginalPath:  "/inventory-path",
		SampleReqBody: `{"from":"inventory"}`,
		SampleHeaders: map[string][]string{"X-Source": {"inventory"}},
	}
	merged := ApplyTrafficSampleToInventory(inventory, &core.TrafficSample{
		ReqBody:      `{"from":"sample"}`,
		OriginalPath: "/sample-path",
		ReqHeaders:   map[string][]string{"X-Source": {"sample"}},
	})

	if merged.SampleReqBody != `{"from":"sample"}` {
		t.Fatalf("unexpected body: %s", merged.SampleReqBody)
	}
	if merged.OriginalPath != "/sample-path" {
		t.Fatalf("unexpected path: %s", merged.OriginalPath)
	}
	if merged.SampleHeaders["X-Source"][0] != "sample" {
		t.Fatalf("unexpected headers: %+v", merged.SampleHeaders)
	}
	if merged.BaseURL != inventory.BaseURL {
		t.Fatalf("empty sample base URL must not overwrite inventory base URL")
	}
}
