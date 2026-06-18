package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/security/securetoken"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ConnectorResponse struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Recommended bool   `json:"recommended,omitempty"`
}

type QuickStartResponse struct {
	ConfiguredItems []string             `json:"configured_items"`
	InventoryCount  int64                `json:"inventory_count"`
	DataSources     []DataSourceResponse `json:"data_sources"`
	Connectors      []ConnectorResponse  `json:"connectors"`
}

type DataSourceRequest struct {
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	TargetURL string            `json:"target_url"`
	Config    map[string]string `json:"config"`
}

type DataSourceResponse struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	TargetURL string            `json:"target_url,omitempty"`
	Config    map[string]string `json:"config,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type AgentEnrollmentRequest struct {
	DataSourceID string `json:"data_source_id"`
	Name         string `json:"name"`
	TTLHours     int    `json:"ttl_hours"`
}

type AgentEnrollmentResponse struct {
	EnrollmentID        string    `json:"enrollment_id"`
	DataSourceID        string    `json:"data_source_id"`
	EnrollmentToken     string    `json:"enrollment_token"`
	ExpiresAt           time.Time `json:"expires_at"`
	RegistrationCommand string    `json:"registration_command"`
	AgentRunHint        string    `json:"agent_run_hint"`
}

type AgentRegisterRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	AgentName       string `json:"agent_name"`
}

type AgentRegisterResponse struct {
	AgentID      string `json:"agent_id"`
	AccountID    string `json:"account_id"`
	DataSourceID string `json:"data_source_id"`
	AgentToken   string `json:"agent_token"`
	TokenType    string `json:"token_type"`
}

func (s *Server) handleQuickStartState(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.AccountID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	accountID, err := primitive.ObjectIDFromHex(principal.AccountID)
	if err != nil {
		http.Error(w, "Invalid account", http.StatusUnauthorized)
		return
	}
	sources, err := s.DB.ListDataSources(accountID)
	if err != nil {
		http.Error(w, "Failed to load data sources", http.StatusInternalServerError)
		return
	}
	inventoryCount, err := s.DB.CountInventoryForAccount(accountID)
	if err != nil {
		http.Error(w, "Failed to load inventory state", http.StatusInternalServerError)
		return
	}
	configured := make([]string, 0, len(sources)+1)
	responses := make([]DataSourceResponse, 0, len(sources))
	for _, source := range sources {
		configured = append(configured, source.Type)
		responses = append(responses, dataSourceResponse(source))
	}
	if inventoryCount > 0 {
		configured = append(configured, "INVENTORY")
	}
	writeJSON(w, http.StatusOK, QuickStartResponse{
		ConfiguredItems: configured,
		InventoryCount:  inventoryCount,
		DataSources:     responses,
		Connectors:      quickStartConnectors(),
	})
}

func (s *Server) handleListDataSources(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.AccountID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	accountID, err := primitive.ObjectIDFromHex(principal.AccountID)
	if err != nil {
		http.Error(w, "Invalid account", http.StatusUnauthorized)
		return
	}
	sources, err := s.DB.ListDataSources(accountID)
	if err != nil {
		http.Error(w, "Failed to load data sources", http.StatusInternalServerError)
		return
	}
	out := make([]DataSourceResponse, 0, len(sources))
	for _, source := range sources {
		out = append(out, dataSourceResponse(source))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": out})
}

func (s *Server) handleCreateDataSource(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.AccountID == "" || principal.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req DataSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	sourceType, err := validateDataSourceType(req.Type)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	targetURL := strings.TrimSpace(req.TargetURL)
	if sourceType == core.DataSourceTypeActiveURL {
		if err := validateHTTPURL(targetURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	accountID, _ := primitive.ObjectIDFromHex(principal.AccountID)
	userID, _ := primitive.ObjectIDFromHex(principal.UserID)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = defaultDataSourceName(sourceType)
	}
	source, err := s.DB.CreateDataSource(core.DataSource{
		AccountID: accountID,
		Type:      sourceType,
		Name:      name,
		Status:    core.DataSourceStatusPending,
		TargetURL: targetURL,
		Config:    sanitizedSourceConfig(req.Config),
		CreatedBy: userID,
	})
	if err != nil {
		http.Error(w, "Failed to create data source", http.StatusInternalServerError)
		return
	}
	s.auditDataSource(r, core.AuditActionDataSourceCreate, core.AuditStatusSuccess, source.ID.Hex(), "")
	writeJSON(w, http.StatusCreated, dataSourceResponse(source))
}

func (s *Server) handleCreateAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.AccountID == "" || principal.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var req AgentEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	sourceID, err := primitive.ObjectIDFromHex(strings.TrimSpace(req.DataSourceID))
	if err != nil {
		http.Error(w, "Invalid data_source_id", http.StatusBadRequest)
		return
	}
	accountID, _ := primitive.ObjectIDFromHex(principal.AccountID)
	userID, _ := primitive.ObjectIDFromHex(principal.UserID)
	source, err := s.DB.GetDataSourceForAccount(accountID, sourceID)
	if err != nil {
		if errors.Is(err, db.ErrDataSourceNotFound) {
			http.Error(w, "Data source not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to load data source", http.StatusInternalServerError)
		return
	}
	if source.Type != core.DataSourceTypeEBPFLinux && source.Type != core.DataSourceTypeEBPFKubernetes {
		http.Error(w, "Agent enrollment is only valid for eBPF data sources", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if ttl > 7*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}
	token, err := securetoken.Generate("kx_enroll")
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	enrollment, err := s.DB.CreateAgentEnrollment(core.AgentEnrollment{
		AccountID:    accountID,
		DataSourceID: source.ID,
		TokenHash:    securetoken.Hash(token),
		Name:         strings.TrimSpace(req.Name),
		CreatedBy:    userID,
		ExpiresAt:    time.Now().UTC().Add(ttl),
	})
	if err != nil {
		http.Error(w, "Failed to create enrollment", http.StatusInternalServerError)
		return
	}
	s.auditDataSource(r, core.AuditActionAgentEnrollmentCreate, core.AuditStatusSuccess, enrollment.ID.Hex(), "")
	writeJSON(w, http.StatusCreated, AgentEnrollmentResponse{
		EnrollmentID:        enrollment.ID.Hex(),
		DataSourceID:        source.ID.Hex(),
		EnrollmentToken:     token,
		ExpiresAt:           enrollment.ExpiresAt,
		RegistrationCommand: fmt.Sprintf(`curl -s -X POST "$KARAXYS_BACKEND_URL/agents/register" -H "Content-Type: application/json" -d '{"enrollment_token":"%s","agent_name":"%s"}'`, token, shellSafeName(enrollment.Name)),
		AgentRunHint:        `KARAXYS_BACKEND_URL=http://127.0.0.1:8081 KARAXYS_ENROLLMENT_TOKEN=<token> make local-vampi`,
	})
}

func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req AgentRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	enrollmentToken := strings.TrimSpace(req.EnrollmentToken)
	if enrollmentToken == "" {
		http.Error(w, "enrollment_token is required", http.StatusBadRequest)
		return
	}
	agentToken, err := securetoken.Generate("kx_agent")
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	agent, enrollment, err := s.DB.RegisterAgentFromEnrollment(securetoken.Hash(enrollmentToken), strings.TrimSpace(req.AgentName), securetoken.Hash(agentToken))
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, db.ErrEnrollmentAlreadyUsed) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	_ = s.DB.SaveAuditLog(core.AuditLog{
		ActorType:    core.AuditActorAgent,
		ActorID:      agent.ID.Hex(),
		Action:       core.AuditActionAgentRegister,
		ResourceType: "agent",
		ResourceID:   agent.ID.Hex(),
		Status:       core.AuditStatusSuccess,
		RemoteAddr:   clientID(r),
		Metadata: map[string]string{
			"data_source_id": enrollment.DataSourceID.Hex(),
			"account_id":     enrollment.AccountID.Hex(),
		},
	})
	writeJSON(w, http.StatusCreated, AgentRegisterResponse{
		AgentID:      agent.ID.Hex(),
		AccountID:    agent.AccountID.Hex(),
		DataSourceID: agent.DataSourceID.Hex(),
		AgentToken:   agentToken,
		TokenType:    "Bearer",
	})
}

func (s *Server) authenticateAgentToken(token string) (*ingest.AgentAuth, bool) {
	if token == "" {
		return nil, false
	}
	agent, err := s.DB.FindAgentByTokenHash(securetoken.Hash(token))
	if err != nil {
		return nil, false
	}
	_ = s.DB.MarkAgentSeen(agent.ID)
	return &ingest.AgentAuth{
		AgentID:      agent.ID.Hex(),
		TenantID:     agent.AccountID.Hex(),
		DataSourceID: agent.DataSourceID.Hex(),
	}, true
}

func validateDataSourceType(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case core.DataSourceTypeActiveURL,
		core.DataSourceTypeEBPFLinux,
		core.DataSourceTypeEBPFKubernetes,
		core.DataSourceTypeOpenAPI,
		core.DataSourceTypePostman,
		core.DataSourceTypeHAR:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported data source type %q", value)
	}
}

func validateHTTPURL(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("target_url must be an absolute http(s) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("target_url must use http or https")
	}
	return nil
}

func quickStartConnectors() []ConnectorResponse {
	return []ConnectorResponse{
		{Key: core.DataSourceTypeActiveURL, Label: "Active URL Scan", Description: "Crawl and actively test a reachable API or web application URL.", Category: "DAST", Recommended: true},
		{Key: core.DataSourceTypeEBPFLinux, Label: "eBPF Linux Agent", Description: "Passively capture live API traffic from a Linux host.", Category: "Runtime", Recommended: true},
		{Key: core.DataSourceTypeEBPFKubernetes, Label: "eBPF Kubernetes Agent", Description: "Deploy the eBPF agent as a Kubernetes node-level collector.", Category: "Runtime"},
		{Key: core.DataSourceTypeOpenAPI, Label: "OpenAPI Import", Description: "Import endpoints from an OpenAPI or Swagger specification.", Category: "Import"},
		{Key: core.DataSourceTypePostman, Label: "Postman Import", Description: "Import endpoints from a Postman collection.", Category: "Import"},
		{Key: core.DataSourceTypeHAR, Label: "HAR Upload", Description: "Import browser-captured HTTP traffic from a HAR file.", Category: "Manual"},
	}
}

func dataSourceResponse(source core.DataSource) DataSourceResponse {
	return DataSourceResponse{
		ID:        source.ID.Hex(),
		Type:      source.Type,
		Name:      source.Name,
		Status:    source.Status,
		TargetURL: source.TargetURL,
		Config:    source.Config,
		CreatedAt: source.CreatedAt,
		UpdatedAt: source.UpdatedAt,
	}
}

func defaultDataSourceName(sourceType string) string {
	for _, connector := range quickStartConnectors() {
		if connector.Key == sourceType {
			return connector.Label
		}
	}
	return "Karaxys data source"
}

func sanitizedSourceConfig(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "key") {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func shellSafeName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "karaxys-ebpf-agent"
	}
	value = strings.ReplaceAll(value, `'`, "")
	return value
}

func (s *Server) auditDataSource(r *http.Request, action string, status string, resourceID string, message string) {
	principal, _ := PrincipalFromContext(r.Context())
	_ = s.DB.SaveAuditLog(core.AuditLog{
		ActorType:    core.AuditActorUser,
		ActorID:      principal.UserID,
		Action:       action,
		ResourceType: "data_source",
		ResourceID:   resourceID,
		Status:       status,
		RemoteAddr:   clientID(r),
		Message:      message,
		Metadata: map[string]string{
			"account_id": principal.AccountID,
		},
	})
}
