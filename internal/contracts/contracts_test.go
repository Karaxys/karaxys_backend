package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestContractExamplesValidate(t *testing.T) {
	t.Run("raw network", func(t *testing.T) {
		var event RawNetworkEvent
		loadExample(t, "raw.network.v1.example.json", &event)
		if err := ValidateRawNetworkEvent(event); err != nil {
			t.Fatalf("raw network example failed validation: %v", err)
		}
	})

	t.Run("http conversation", func(t *testing.T) {
		var conversation HTTPConversation
		loadExample(t, "http.conversation.v1.example.json", &conversation)
		if err := ValidateHTTPConversation(conversation); err != nil {
			t.Fatalf("http conversation example failed validation: %v", err)
		}
	})

	t.Run("scan job", func(t *testing.T) {
		var job ScanJob
		loadExample(t, "scan.job.v1.example.json", &job)
		if err := ValidateScanJob(job); err != nil {
			t.Fatalf("scan job example failed validation: %v", err)
		}
	})

	t.Run("scan result", func(t *testing.T) {
		var result ScanResult
		loadExample(t, "scan.result.v1.example.json", &result)
		if err := ValidateScanResult(result); err != nil {
			t.Fatalf("scan result example failed validation: %v", err)
		}
	})
}

func TestSchemaFilesAreValidJSON(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "contracts", "schemas", "*.json"))
	if err != nil {
		t.Fatalf("glob schema files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected schema files")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			var parsed map[string]any
			if err := json.Unmarshal(raw, &parsed); err != nil {
				t.Fatalf("schema is not valid JSON: %v", err)
			}
			if parsed["$schema"] == "" {
				t.Fatal("schema is missing $schema")
			}
			if parsed["$id"] == "" {
				t.Fatal("schema is missing $id")
			}
		})
	}
}

func TestRawNetworkEventRejectsSizeMismatch(t *testing.T) {
	var event RawNetworkEvent
	loadExample(t, "raw.network.v1.example.json", &event)

	event.Size++

	if err := ValidateRawNetworkEvent(event); err == nil {
		t.Fatal("expected raw network event validation to reject mismatched payload size")
	}
}

func TestHTTPConversationRejectsInvalidObjectID(t *testing.T) {
	var conversation HTTPConversation
	loadExample(t, "http.conversation.v1.example.json", &conversation)

	conversation.ID.OID = "not-an-object-id"

	if err := ValidateHTTPConversation(conversation); err == nil {
		t.Fatal("expected http conversation validation to reject invalid ObjectID")
	}
}

func TestDecodeAndValidateHTTPConversationAcceptsSchemaValidExample(t *testing.T) {
	raw := loadExampleRaw(t, "http.conversation.v1.example.json")

	conversation, err := DecodeAndValidateHTTPConversation(raw)
	if err != nil {
		t.Fatalf("expected example to pass schema validation: %v", err)
	}
	if conversation.SchemaVersion != SchemaHTTPConversationV1 {
		t.Fatalf("unexpected schema version: %s", conversation.SchemaVersion)
	}
}

func TestDecodeAndValidateHTTPConversationRejectsSchemaViolation(t *testing.T) {
	var conversation HTTPConversation
	loadExample(t, "http.conversation.v1.example.json", &conversation)
	conversation.HTTP.Request.Method = "get"
	raw, err := json.Marshal(conversation)
	if err != nil {
		t.Fatalf("encode invalid conversation: %v", err)
	}

	if _, err := DecodeAndValidateHTTPConversation(raw); err == nil {
		t.Fatal("expected schema validation to reject lowercase method")
	}
}

func TestScanJobRequiresSecretReference(t *testing.T) {
	var job ScanJob
	loadExample(t, "scan.job.v1.example.json", &job)

	job.Auth.SecretRef = ""

	if err := ValidateScanJob(job); err == nil {
		t.Fatal("expected scan job validation to require secret_ref for secret_ref auth mode")
	}
}

func TestScanResultRejectsInvalidDigest(t *testing.T) {
	var result ScanResult
	loadExample(t, "scan.result.v1.example.json", &result)

	result.Response.BodySHA256 = "not-a-sha256"

	if err := ValidateScanResult(result); err == nil {
		t.Fatal("expected scan result validation to reject invalid body_sha256")
	}
}

func loadExample(t *testing.T, name string, target any) {
	t.Helper()

	raw := loadExampleRaw(t, name)
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode example %s: %v", name, err)
	}
}

func loadExampleRaw(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("..", "..", "contracts", "examples", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example %s: %v", name, err)
	}
	return raw
}
