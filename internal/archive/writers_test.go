package archive

import (
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/objectstore"
	"karaxys_backend/internal/security/redact"
)

type fakeObjectStore struct {
	object objectstore.Object
	body   string
}

func (f *fakeObjectStore) Put(ctx context.Context, object objectstore.Object) error {
	raw, err := io.ReadAll(object.Body)
	if err != nil {
		return err
	}
	f.object = object
	f.body = string(raw)
	return nil
}

func TestMongoBackupWriterUsesStableObjectKey(t *testing.T) {
	store := &fakeObjectStore{}
	writer := MongoBackupWriter{
		Store:  store,
		Prefix: "karaxys-prod",
		Clock:  func() time.Time { return time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC) },
	}

	key, err := writer.WriteDump(context.Background(), "dump archive.gz", strings.NewReader("dump"))
	if err != nil {
		t.Fatalf("write dump: %v", err)
	}
	if key != "karaxys-prod/backups/mongodb/2026/06/19/dump-archive.gz" {
		t.Fatalf("unexpected key: %s", key)
	}
	if store.object.ContentType != mongoDumpContentType || store.body != "dump" {
		t.Fatalf("unexpected stored object: %#v body=%s", store.object, store.body)
	}
}

func TestConversationArchiveWriterRedactsBeforeUpload(t *testing.T) {
	store := &fakeObjectStore{}
	writer := ConversationArchiveWriter{
		Store: store,
		Clock: func() time.Time { return time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC) },
	}

	key, err := writer.WriteConversations(context.Background(), "account-1", []core.TrafficConversation{
		{
			ConversationID: "conversation-1",
			URL:            "https://api.example.com/users?access_token=secret-token-value",
			ReqHeaders:     map[string][]string{"Authorization": {"Bearer secret-token-value"}},
			ReqBody:        `{"password":"secret-token-value"}`,
			RespBody:       `{"token":"secret-token-value"}`,
			CreatedAt:      time.Date(2026, 6, 19, 1, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("write archive: %v", err)
	}
	if key != "archives/conversations/2026/06/19/account-1-010203.ndjson.gz" {
		t.Fatalf("unexpected key: %s", key)
	}
	if store.object.ContentType != conversationArchiveContentType {
		t.Fatalf("unexpected content type: %s", store.object.ContentType)
	}

	reader, err := gzip.NewReader(strings.NewReader(store.body))
	if err != nil {
		t.Fatalf("open gzip archive: %v", err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip archive: %v", err)
	}
	archive := string(raw)
	if strings.Contains(archive, "secret-token-value") {
		t.Fatalf("archive leaked secret: %s", archive)
	}
	if !strings.Contains(archive, redact.Marker) {
		t.Fatalf("archive did not contain redaction marker: %s", archive)
	}
}
