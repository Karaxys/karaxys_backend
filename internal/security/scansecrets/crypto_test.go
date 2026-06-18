package scansecrets

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestProtectorEncryptDecrypt(t *testing.T) {
	protector, err := NewProtector([]byte("12345678901234567890123456789012"), "test-key")
	if err != nil {
		t.Fatalf("new protector: %v", err)
	}

	nonce, ciphertext, err := protector.Encrypt("Bearer secret-token")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if nonce == "" || ciphertext == "" {
		t.Fatalf("expected encoded nonce and ciphertext")
	}
	if strings.Contains(ciphertext, "secret-token") {
		t.Fatalf("ciphertext leaked plaintext: %s", ciphertext)
	}

	plaintext, err := protector.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plaintext != "Bearer secret-token" {
		t.Fatalf("unexpected plaintext: %s", plaintext)
	}
}

func TestProtectorRejectsInvalidKeySize(t *testing.T) {
	if _, err := NewProtector([]byte("short"), ""); err == nil {
		t.Fatalf("expected invalid key size error")
	}
}

func TestFromEnvRequiresKey(t *testing.T) {
	t.Setenv(EnvSecretKeyB64, "")
	t.Setenv(EnvSecretKey, "")

	_, err := FromEnv()
	if !errors.Is(err, ErrSecretKeyMissing) {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestFromEnvLoadsRawKey(t *testing.T) {
	t.Setenv(EnvSecretKeyB64, "")
	t.Setenv(EnvSecretKey, "12345678901234567890123456789012")

	protector, err := FromEnv()
	if err != nil {
		t.Fatalf("from env: %v", err)
	}
	if protector.KeyID() == "" {
		t.Fatalf("expected key id")
	}
}

func TestFromEnvPrefersBase64Key(t *testing.T) {
	t.Setenv(EnvSecretKeyB64, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	t.Setenv(EnvSecretKey, strings.Repeat("x", 32))

	protector, err := FromEnv()
	if err != nil {
		t.Fatalf("from env: %v", err)
	}
	nonce, ciphertext, err := protector.Encrypt("secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plaintext, err := protector.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plaintext != "secret" {
		t.Fatalf("unexpected plaintext: %s", plaintext)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
