package core

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestScanConfigDoesNotMarshalManualAuth(t *testing.T) {
	config := ScanConfig{
		TargetURL:     "http://api.example.local",
		Method:        "GET",
		Path:          "/users",
		TestType:      "BOLA",
		AuthSecretRef: "6650f8cb1c5e7c6c1f93a111",
		ManualAuth:    "Bearer secret-token",
	}

	raw, err := bson.Marshal(config)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := bson.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, exists := decoded["manual_auth"]; exists {
		t.Fatalf("manual_auth should not be persisted: %+v", decoded)
	}
	if decoded["auth_secret_ref"] != config.AuthSecretRef {
		t.Fatalf("auth_secret_ref was not persisted: %+v", decoded)
	}
}
