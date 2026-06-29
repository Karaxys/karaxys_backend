package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/security/securetoken"
)

const (
	accountTokenHeader    = "X-Karaxys-Account-Token"
	maxAccountIngestBytes = 10 * 1024 * 1024 // 10 MiB for batches
	maxBatchSize          = 500
)

// handleAccountIngest processes POST /ingest — the Akto-style account-token ingest path.
//
// Auth: Authorization: Bearer <token>  OR  X-Karaxys-Account-Token: <token>
// Body: a single http.conversation.v1 JSON object, OR a JSON array of them.
// The tenant_id is always set server-side from the account token; the client
// cannot influence which account data lands in.
func (s *Server) handleAccountIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// ── 1. Extract and validate account token ────────────────────────────────
	rawToken := bearerTokenFromRequest(r)
	if rawToken == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenHash := securetoken.Hash(rawToken)

	tok, err := s.DB.FindAccountByIngestToken(r.Context(), tokenHash)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	accountID := tok.AccountID
	tenantID := accountID.Hex()

	// Fire-and-forget last-used update — must not block ingestion.
	go s.DB.TouchIngestToken(r.Context(), accountID)

	// ── 2. Content-type check ────────────────────────────────────────────────
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// ── 3. Read body with hard cap ───────────────────────────────────────────
	r.Body = http.MaxBytesReader(w, r.Body, maxAccountIngestBytes)
	defer r.Body.Close()

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	// ── 4. Detect single vs batch payload ───────────────────────────────────
	var rawItems []json.RawMessage
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &rawItems); err != nil {
			http.Error(w, "Invalid JSON array", http.StatusBadRequest)
			return
		}
		if len(rawItems) == 0 {
			writeIngestResponse(w, 0, 0, 0)
			return
		}
		if len(rawItems) > maxBatchSize {
			http.Error(w, "Batch exceeds maximum size", http.StatusRequestEntityTooLarge)
			return
		}
	} else if raw[0] == '{' {
		rawItems = []json.RawMessage{json.RawMessage(raw)}
	} else {
		http.Error(w, "Body must be a JSON object or array", http.StatusBadRequest)
		return
	}

	// ── 5. Process each conversation ─────────────────────────────────────────
	if s.Ingest == nil {
		http.Error(w, "Ingestion service unavailable", http.StatusServiceUnavailable)
		return
	}

	var accepted, duplicated, dropped int
	remoteAddr := r.RemoteAddr

	for _, item := range rawItems {
		status, processErr := s.Ingest.ProcessConversationForTenant(r.Context(), item, tenantID, remoteAddr)
		if processErr != nil {
			var ingestErr *ingest.IngestProcessError
			if errors.As(processErr, &ingestErr) {
				// Validation errors abort the whole batch with the error code.
				// Transient persistence errors are also surfaced to the client so
				// it can retry rather than silently losing data.
				http.Error(w, ingestErr.Msg, ingestErr.Code)
				return
			}
			http.Error(w, "Internal ingestion error", http.StatusInternalServerError)
			return
		}
		switch status {
		case "accepted":
			accepted++
		case "duplicate":
			duplicated++
		case "dropped":
			dropped++
		}
	}

	// ── 6. Update data source status (fire-and-forget) ───────────────────────
	// Only bother when at least one conversation was actually accepted.
	if accepted > 0 {
		go func() {
			if err := s.DB.MarkIngestTrafficSeen(r.Context(), accountID); err != nil {
				log.Printf("MarkIngestTrafficSeen account=%s: %v", tenantID, err)
			}
		}()
	}

	// ── 7. Respond ───────────────────────────────────────────────────────────
	writeIngestResponse(w, accepted, duplicated, dropped)
}

type ingestResponse struct {
	Accepted   int `json:"accepted"`
	Duplicated int `json:"duplicated"`
	Dropped    int `json:"dropped"`
}

func writeIngestResponse(w http.ResponseWriter, accepted, duplicated, dropped int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ingestResponse{
		Accepted:   accepted,
		Duplicated: duplicated,
		Dropped:    dropped,
	})
}

// bearerTokenFromRequest extracts the token from Authorization: Bearer <tok>
// or X-Karaxys-Account-Token header, in that order.
// bearerToken is defined in middleware.go.
func bearerTokenFromRequest(r *http.Request) string {
	if tok := bearerToken(r.Header.Get("Authorization")); tok != "" {
		return tok
	}
	return strings.TrimSpace(r.Header.Get(accountTokenHeader))
}

func isJSONContentType(v string) bool {
	if v == "" {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(v, ";")[0]))
	return mediaType == "application/json"
}
