package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

const httpConversationSchemaFile = "http.conversation.v1.schema.json"

var (
	httpSchemaOnce sync.Once
	httpSchema     *gojsonschema.Schema
	httpSchemaErr  error
)

func DecodeAndValidateHTTPConversation(raw []byte) (HTTPConversation, error) {
	if err := validateHTTPConversationSchema(raw); err != nil {
		return HTTPConversation{}, err
	}

	var conversation HTTPConversation
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&conversation); err != nil {
		return HTTPConversation{}, fmt.Errorf("decode http conversation: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return HTTPConversation{}, fmt.Errorf("decode http conversation: trailing JSON")
	}
	if err := ValidateHTTPConversation(conversation); err != nil {
		return HTTPConversation{}, err
	}
	return conversation, nil
}

func validateHTTPConversationSchema(raw []byte) error {
	httpSchemaOnce.Do(func() {
		path, err := contractSchemaPath(httpConversationSchemaFile)
		if err != nil {
			httpSchemaErr = err
			return
		}
		httpSchema, httpSchemaErr = gojsonschema.NewSchema(gojsonschema.NewReferenceLoader("file://" + filepath.ToSlash(path)))
	})
	if httpSchemaErr != nil {
		return httpSchemaErr
	}

	result, err := httpSchema.Validate(gojsonschema.NewBytesLoader(raw))
	if err != nil {
		return fmt.Errorf("validate http conversation schema: %w", err)
	}
	if result.Valid() {
		return nil
	}

	messages := make([]string, 0, len(result.Errors()))
	for _, schemaErr := range result.Errors() {
		messages = append(messages, schemaErr.String())
	}
	return fmt.Errorf("http conversation schema validation failed: %s", strings.Join(messages, "; "))
}

func contractSchemaPath(fileName string) (string, error) {
	if dir := os.Getenv("KARAXYS_CONTRACTS_DIR"); dir != "" {
		path := filepath.Join(dir, "schemas", fileName)
		if _, err := os.Stat(path); err == nil {
			return filepath.Abs(path)
		}
	}

	candidates := []string{
		filepath.Join("contracts", "schemas", fileName),
		filepath.Join("..", "contracts", "schemas", fileName),
		filepath.Join("..", "..", "contracts", "schemas", fileName),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Abs(candidate)
		}
	}
	return "", fmt.Errorf("contract schema %q not found", fileName)
}
