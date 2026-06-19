package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"karaxys_backend/internal/core"
)

func TestRequireRolesAllowsConfiguredRole(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, Principal{
		ActorType: core.AuditActorUser,
		UserID:    "user-1",
		AccountID: "507f1f77bcf86cd799439011",
		Role:      core.UserRoleAnalyst,
	}))
	rec := httptest.NewRecorder()

	principal, ok := server.requireRoles(rec, req, readRoles...)
	if !ok {
		t.Fatalf("expected role to be allowed, status=%d body=%s", rec.Code, rec.Body.String())
	}
	if principal.Role != core.UserRoleAnalyst {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestRequireRolesRejectsDisallowedRole(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, Principal{
		ActorType: core.AuditActorUser,
		UserID:    "user-1",
		AccountID: "507f1f77bcf86cd799439011",
		Role:      core.UserRoleReadOnly,
	}))
	rec := httptest.NewRecorder()

	if _, ok := server.requireRoles(rec, req, scanRoles...); ok {
		t.Fatalf("expected read-only role to be rejected for scan")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireRolesDefaultsAPIKeyRoleToAdmin(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/data-sources", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, Principal{
		ActorType: core.AuditActorAPIKey,
		AccountID: "507f1f77bcf86cd799439011",
	}))
	rec := httptest.NewRecorder()

	principal, ok := server.requireRoles(rec, req, adminOnlyRoles...)
	if !ok {
		t.Fatalf("expected API key to default to admin, status=%d body=%s", rec.Code, rec.Body.String())
	}
	if principal.Role != core.UserRoleAdmin {
		t.Fatalf("unexpected principal role: %+v", principal)
	}
}
