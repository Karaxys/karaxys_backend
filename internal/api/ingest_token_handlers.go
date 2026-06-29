package api

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/scansecrets"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ingestTokenResponse is the shape returned to the dashboard for token display.
type ingestTokenResponse struct {
	ID          string    `json:"id"`
	TokenPrefix string    `json:"token_prefix"`
	Token       string    `json:"token"`
	IngestURL   string    `json:"ingest_url"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
}

// handleGetIngestToken returns the account-level ingest token, creating it on the
// first call. The raw token is always returned (stored encrypted at rest, so it's
// always recoverable without rotation — unlike display-once PAT models).
//
// GET /account/ingest-token
func (s *Server) handleGetIngestToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, adminOnlyRoles...)
	if !ok {
		return
	}
	accountID, hasAccount, err := scopedAccountID(principal)
	if err != nil || !hasAccount {
		http.Error(w, "Account ID required", http.StatusBadRequest)
		return
	}

	protector := ingestTokenProtector()
	tok, rawToken, err := s.DB.GetOrCreateAccountIngestToken(r.Context(), accountID, protector)
	if err != nil {
		log.Printf("GetOrCreateAccountIngestToken account=%s: %v", accountID.Hex(), err)
		http.Error(w, "Failed to retrieve ingest token", http.StatusInternalServerError)
		return
	}

	s.auditIngestToken(r, core.AuditActionIngestTokenAccess, core.AuditStatusSuccess, principal.UserID, accountID.Hex(), "")
	writeJSON(w, http.StatusOK, buildIngestTokenResponse(tok, rawToken))
}

// handleRotateIngestToken invalidates the current token and issues a new one.
// All collectors using the old token will stop ingesting until reconfigured with
// the new token — this is intentional (revocation semantics).
//
// POST /account/ingest-token/rotate
func (s *Server) handleRotateIngestToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, adminOnlyRoles...)
	if !ok {
		return
	}
	accountID, hasAccount, err := scopedAccountID(principal)
	if err != nil || !hasAccount {
		http.Error(w, "Account ID required", http.StatusBadRequest)
		return
	}

	protector := ingestTokenProtector()
	tok, rawToken, err := s.DB.RotateAccountIngestToken(r.Context(), accountID, protector)
	if err != nil {
		log.Printf("RotateAccountIngestToken account=%s: %v", accountID.Hex(), err)
		http.Error(w, "Failed to rotate ingest token", http.StatusInternalServerError)
		return
	}

	s.auditIngestToken(r, core.AuditActionIngestTokenRotate, core.AuditStatusSuccess, principal.UserID, accountID.Hex(), "")
	writeJSON(w, http.StatusOK, buildIngestTokenResponse(tok, rawToken))
}

// ensureAccountIngestToken is called from the signup flow to pre-create the token
// so it's immediately available when the user lands on the Quick Start page.
// It runs in a background goroutine so it never delays the signup response.
func (s *Server) ensureAccountIngestToken(accountID primitive.ObjectID) {
	protector := ingestTokenProtector()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, err := s.DB.GetOrCreateAccountIngestToken(ctx, accountID, protector); err != nil {
		log.Printf("ensureAccountIngestToken account=%s: %v", accountID.Hex(), err)
	}
}

// ingestTokenProtector loads the AES protector from env, or returns nil in dev
// mode (when KARAXYS_SECRET_KEY_B64 is unset). Nil is handled gracefully in the
// repository — tokens are stored plaintext with a sentinel nonce in dev.
func ingestTokenProtector() *scansecrets.Protector {
	p, err := scansecrets.FromEnv()
	if err != nil {
		return nil
	}
	return p
}

func buildIngestTokenResponse(tok *core.AccountIngestToken, rawToken string) ingestTokenResponse {
	return ingestTokenResponse{
		ID:          tok.ID.Hex(),
		TokenPrefix: tok.TokenPrefix,
		Token:       rawToken,
		IngestURL:   ingestPublicURL(),
		CreatedAt:   tok.CreatedAt,
		UpdatedAt:   tok.UpdatedAt,
		RotatedAt:   tok.RotatedAt,
		LastUsedAt:  tok.LastUsedAt,
	}
}

// ingestPublicURL returns the full externally-reachable URL for POST /ingest.
// KARAXYS_PUBLIC_API_BASE_URL is set in docker-compose for the dashboard service;
// falls back to localhost for local development.
func ingestPublicURL() string {
	base := os.Getenv("KARAXYS_PUBLIC_API_BASE_URL")
	if base == "" {
		base = "http://localhost:8081"
	}
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base + "/ingest"
}

func (s *Server) auditIngestToken(r *http.Request, action, status, userID, accountID, message string) {
	_ = s.DB.SaveAuditLog(core.AuditLog{
		ActorType:    core.AuditActorUser,
		ActorID:      userID,
		Action:       action,
		ResourceType: "ingest_token",
		ResourceID:   accountID,
		Status:       status,
		RemoteAddr:   r.RemoteAddr,
		Message:      message,
	})
}
