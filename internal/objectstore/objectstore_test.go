package objectstore

import "testing"

func TestLoadS3ConfigFromEnv(t *testing.T) {
	t.Setenv("KARAXYS_OBJECTSTORE_BUCKET", "karaxys-prod")
	t.Setenv("KARAXYS_OBJECTSTORE_REGION", "")
	t.Setenv("KARAXYS_OBJECTSTORE_ENDPOINT", "http://127.0.0.1:9000")
	t.Setenv("KARAXYS_OBJECTSTORE_FORCE_PATH_STYLE", "true")
	t.Setenv("KARAXYS_OBJECTSTORE_SSE", "AES256")

	cfg := LoadS3ConfigFromEnv()
	if cfg.Bucket != "karaxys-prod" || cfg.Region != "us-east-1" || cfg.EndpointURL != "http://127.0.0.1:9000" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if !cfg.ForcePathStyle || cfg.ServerSideEncryption != "AES256" {
		t.Fatalf("unexpected storage options: %#v", cfg)
	}
}
