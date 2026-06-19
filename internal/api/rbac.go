package api

import (
	"net/http"
	"strings"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	readRoles         = []string{core.UserRoleAdmin, core.UserRoleAnalyst, core.UserRoleScanner, core.UserRoleReadOnly}
	scanRoles         = []string{core.UserRoleAdmin, core.UserRoleAnalyst, core.UserRoleScanner}
	adminOnlyRoles    = []string{core.UserRoleAdmin}
	settingsReadRoles = []string{core.UserRoleAdmin, core.UserRoleAnalyst, core.UserRoleReadOnly}
)

func (s *Server) requireRoles(w http.ResponseWriter, r *http.Request, allowedRoles ...string) (Principal, bool) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return Principal{}, false
	}
	role := strings.TrimSpace(principal.Role)
	if role == "" && principal.ActorType == core.AuditActorAPIKey {
		role = core.UserRoleAdmin
		principal.Role = role
	}
	for _, allowed := range allowedRoles {
		if role == allowed {
			return principal, true
		}
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
	return Principal{}, false
}

func scopedAccountID(principal Principal) (primitive.ObjectID, bool, error) {
	if strings.TrimSpace(principal.AccountID) == "" {
		return primitive.NilObjectID, false, nil
	}
	accountID, err := primitive.ObjectIDFromHex(principal.AccountID)
	if err != nil {
		return primitive.NilObjectID, true, err
	}
	return accountID, true, nil
}

func normalizeAPIKeyRole(role string) string {
	role = strings.TrimSpace(role)
	switch role {
	case core.UserRoleAdmin, core.UserRoleAnalyst, core.UserRoleScanner, core.UserRoleReadOnly:
		return role
	default:
		return core.UserRoleAdmin
	}
}
