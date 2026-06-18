package scansecrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	EnvSecretKeyB64 = "KARAXYS_SECRET_KEY_B64"
	EnvSecretKey    = "KARAXYS_SECRET_KEY"
	defaultKeyID    = "local-env-v1"
	keySizeBytes    = 32
)

var ErrSecretKeyMissing = errors.New("scan secret encryption key is not configured")

type Protector struct {
	key   []byte
	keyID string
}

func FromEnv() (*Protector, error) {
	if encoded := os.Getenv(EnvSecretKeyB64); encoded != "" {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s must be base64 encoded: %w", EnvSecretKeyB64, err)
		}
		return NewProtector(key, defaultKeyID)
	}

	if raw := os.Getenv(EnvSecretKey); raw != "" {
		return NewProtector([]byte(raw), defaultKeyID)
	}

	return nil, ErrSecretKeyMissing
}

func NewProtector(key []byte, keyID string) (*Protector, error) {
	if len(key) != keySizeBytes {
		return nil, fmt.Errorf("scan secret encryption key must be %d bytes", keySizeBytes)
	}
	if keyID == "" {
		keyID = defaultKeyID
	}
	copied := make([]byte, len(key))
	copy(copied, key)
	return &Protector{key: copied, keyID: keyID}, nil
}

func (p *Protector) KeyID() string {
	if p == nil {
		return ""
	}
	return p.keyID
}

func (p *Protector) Encrypt(plaintext string) (string, string, error) {
	if p == nil {
		return "", "", ErrSecretKeyMissing
	}
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (p *Protector) Decrypt(nonceEncoded string, ciphertextEncoded string) (string, error) {
	if p == nil {
		return "", ErrSecretKeyMissing
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceEncoded)
	if err != nil {
		return "", fmt.Errorf("decode scan secret nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextEncoded)
	if err != nil {
		return "", fmt.Errorf("decode scan secret ciphertext: %w", err)
	}
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt scan secret: %w", err)
	}
	return string(plaintext), nil
}
