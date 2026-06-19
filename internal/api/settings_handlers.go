package api

import (
	"encoding/json"
	"net/http"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	minRetentionHours  = 1
	maxRetentionHours  = 168
	minTrafficEventCap = 100
	maxTrafficEventCap = 100000
)

type SecuritySettingsRequest struct {
	RetentionHours   *int  `json:"retention_hours"`
	MaxTrafficEvents *int  `json:"max_traffic_events"`
	RedactionEnabled *bool `json:"redaction_enabled"`
}

type SecuritySettingsResponse struct {
	ID               string `json:"id"`
	AccountID        string `json:"account_id"`
	RetentionHours   int    `json:"retention_hours"`
	MaxTrafficEvents int    `json:"max_traffic_events"`
	RedactionEnabled bool   `json:"redaction_enabled"`
	UpdatedAt        string `json:"updated_at"`
}

func (s *Server) handleGetSecuritySettings(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, settingsReadRoles...)
	if !ok {
		return
	}
	accountID, ok := requireAccountObjectID(w, principal)
	if !ok {
		return
	}
	settings, err := s.DB.GetOrCreateAccountSettings(accountID)
	if err != nil {
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, securitySettingsResponse(settings))
}

func (s *Server) handleUpdateSecuritySettings(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, adminOnlyRoles...)
	if !ok {
		return
	}
	accountID, ok := requireAccountObjectID(w, principal)
	if !ok {
		return
	}
	var req SecuritySettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditSettings(r, core.AuditStatusFailure, "invalid json")
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	current, err := s.DB.GetOrCreateAccountSettings(accountID)
	if err != nil {
		s.auditSettings(r, core.AuditStatusFailure, "settings load failed")
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}
	retentionHours := current.RetentionHours
	if req.RetentionHours != nil {
		retentionHours = *req.RetentionHours
	}
	maxTrafficEvents := current.MaxTrafficEvents
	if req.MaxTrafficEvents != nil {
		maxTrafficEvents = *req.MaxTrafficEvents
	}
	if retentionHours < minRetentionHours || retentionHours > maxRetentionHours {
		s.auditSettings(r, core.AuditStatusFailure, "invalid retention_hours")
		http.Error(w, "retention_hours must be between 1 and 168", http.StatusBadRequest)
		return
	}
	if maxTrafficEvents < minTrafficEventCap || maxTrafficEvents > maxTrafficEventCap {
		s.auditSettings(r, core.AuditStatusFailure, "invalid max_traffic_events")
		http.Error(w, "max_traffic_events must be between 100 and 100000", http.StatusBadRequest)
		return
	}
	if req.RedactionEnabled != nil && !*req.RedactionEnabled {
		s.auditSettings(r, core.AuditStatusFailure, "redaction cannot be disabled")
		http.Error(w, "redaction_enabled cannot be disabled", http.StatusBadRequest)
		return
	}
	updatedBy := primitive.NilObjectID
	if principal.UserID != "" {
		updatedBy, err = primitive.ObjectIDFromHex(principal.UserID)
		if err != nil {
			s.auditSettings(r, core.AuditStatusFailure, "invalid user")
			http.Error(w, "Invalid user", http.StatusUnauthorized)
			return
		}
	}
	settings, err := s.DB.UpdateAccountSettings(accountID, updatedBy, retentionHours, maxTrafficEvents)
	if err != nil {
		s.auditSettings(r, core.AuditStatusFailure, "settings update failed")
		http.Error(w, "Failed to update settings", http.StatusInternalServerError)
		return
	}
	s.auditSettings(r, core.AuditStatusSuccess, "")
	writeJSON(w, http.StatusOK, securitySettingsResponse(settings))
}

func requireAccountObjectID(w http.ResponseWriter, principal Principal) (primitive.ObjectID, bool) {
	if principal.AccountID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return primitive.NilObjectID, false
	}
	accountID, err := primitive.ObjectIDFromHex(principal.AccountID)
	if err != nil {
		http.Error(w, "Invalid account", http.StatusUnauthorized)
		return primitive.NilObjectID, false
	}
	return accountID, true
}

func securitySettingsResponse(settings core.AccountSettings) SecuritySettingsResponse {
	return SecuritySettingsResponse{
		ID:               settings.ID.Hex(),
		AccountID:        settings.AccountID.Hex(),
		RetentionHours:   settings.RetentionHours,
		MaxTrafficEvents: settings.MaxTrafficEvents,
		RedactionEnabled: settings.RedactionEnabled,
		UpdatedAt:        settings.UpdatedAt.Format("2006-01-02T15:04:05.000Z07:00"),
	}
}

func (s *Server) auditSettings(r *http.Request, status string, message string) {
	principal, _ := PrincipalFromContext(r.Context())
	actorID := principal.UserID
	if actorID == "" {
		actorID = SubjectFromContext(r.Context())
	}
	actorType := principal.ActorType
	if actorType == "" {
		actorType = core.AuditActorUser
	}
	_ = s.DB.SaveAuditLog(core.AuditLog{
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       core.AuditActionSettingsUpdate,
		ResourceType: "account_settings",
		ResourceID:   principal.AccountID,
		Status:       status,
		RemoteAddr:   clientID(r),
		Message:      message,
		Metadata: map[string]string{
			"account_id": principal.AccountID,
		},
	})
}
