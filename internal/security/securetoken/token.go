package securetoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const defaultRandomBytes = 32

func Generate(prefix string) (string, error) {
	raw := make([]byte, defaultRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return token, nil
	}
	return prefix + "_" + token, nil
}

func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
