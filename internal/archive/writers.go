package archive

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/objectstore"
	"karaxys_backend/internal/security/redact"
)

const (
	mongoDumpContentType           = "application/gzip"
	conversationArchiveContentType = "application/x-ndjson"
)

type MongoBackupWriter struct {
	Store  objectstore.Writer
	Prefix string
	Clock  func() time.Time
}

type ConversationArchiveWriter struct {
	Store  objectstore.Writer
	Prefix string
	Clock  func() time.Time
}

func (w MongoBackupWriter) WriteDump(ctx context.Context, name string, body io.Reader) (string, error) {
	if w.Store == nil {
		return "", fmt.Errorf("object store writer is required")
	}
	if body == nil {
		return "", fmt.Errorf("backup body is required")
	}
	now := writerNow(w.Clock)
	key := objectKey(w.Prefix, "backups/mongodb", now, sanitizeObjectName(name, "mongodump.archive.gz"))
	if err := w.Store.Put(ctx, objectstore.Object{
		Key:         key,
		ContentType: mongoDumpContentType,
		Body:        body,
	}); err != nil {
		return "", err
	}
	return key, nil
}

func (w ConversationArchiveWriter) WriteConversations(ctx context.Context, accountID string, conversations []core.TrafficConversation) (string, error) {
	if w.Store == nil {
		return "", fmt.Errorf("object store writer is required")
	}
	if len(conversations) == 0 {
		return "", fmt.Errorf("at least one conversation is required")
	}
	now := writerNow(w.Clock)
	name := sanitizeObjectName(accountID, "unscoped") + "-" + now.Format("150405") + ".ndjson.gz"
	key := objectKey(w.Prefix, "archives/conversations", now, name)

	reader, writer := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		gzipWriter := gzip.NewWriter(writer)
		encoder := json.NewEncoder(gzipWriter)
		for _, conversation := range conversations {
			if err := encoder.Encode(redact.TrafficConversation(conversation)); err != nil {
				_ = gzipWriter.Close()
				_ = writer.CloseWithError(err)
				errCh <- err
				return
			}
		}
		if err := gzipWriter.Close(); err != nil {
			_ = writer.CloseWithError(err)
			errCh <- err
			return
		}
		errCh <- writer.Close()
	}()

	putErr := w.Store.Put(ctx, objectstore.Object{
		Key:         key,
		ContentType: conversationArchiveContentType,
		Body:        reader,
	})
	writeErr := <-errCh
	if putErr != nil {
		return "", putErr
	}
	if writeErr != nil {
		return "", writeErr
	}
	return key, nil
}

func objectKey(prefix string, category string, now time.Time, name string) string {
	parts := []string{
		strings.Trim(strings.TrimSpace(prefix), "/"),
		strings.Trim(category, "/"),
		now.UTC().Format("2006/01/02"),
		name,
	}
	var clean []string
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			clean = append(clean, part)
		}
	}
	return strings.Join(clean, "/")
}

func sanitizeObjectName(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	var builder strings.Builder
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			builder.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			builder.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			builder.WriteRune(ch)
		case ch == '.', ch == '-', ch == '_':
			builder.WriteRune(ch)
		default:
			builder.WriteRune('-')
		}
	}
	out := strings.Trim(builder.String(), "-")
	if out == "" {
		return fallback
	}
	return out
}

func writerNow(clock func() time.Time) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock().UTC()
}
