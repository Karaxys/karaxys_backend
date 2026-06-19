package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/scanplan"
	"karaxys_backend/internal/security/scansecrets"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Server struct {
	DB     *db.DB
	DBName string
	Ingest *ingest.Service
}

func NewServer(db *db.DB, dbName string, processors ...*analyzer.Processor) *Server {
	var processor *analyzer.Processor
	if len(processors) > 0 {
		processor = processors[0]
	}
	if processor == nil {
		processor = analyzer.NewProcessor(db.Client.Database(dbName))
	}

	return &Server{
		DB:     db,
		DBName: dbName,
		Ingest: ingest.NewService(db, processor, os.Getenv("KARAXYS_AGENT_TOKEN")),
	}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/signup", s.handleSignup)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/me", s.handleMe)
	mux.HandleFunc("GET /quick-start", s.handleQuickStartState)
	mux.HandleFunc("POST /api/fetchQuickStartPageState", s.handleQuickStartState)
	mux.HandleFunc("GET /data-sources", s.handleListDataSources)
	mux.HandleFunc("POST /data-sources", s.handleCreateDataSource)
	mux.HandleFunc("DELETE /data-sources/{id}", s.handleDeleteDataSource)
	mux.HandleFunc("POST /agent-enrollments", s.handleCreateAgentEnrollment)
	mux.HandleFunc("POST /agents/register", s.handleRegisterAgent)
	mux.HandleFunc("GET /settings/security", s.handleGetSecuritySettings)
	mux.HandleFunc("PUT /settings/security", s.handleUpdateSecuritySettings)
	mux.HandleFunc("GET /inventory", s.handleGetInventory)
	mux.HandleFunc("POST /scan", s.handleTriggerScan)
	mux.HandleFunc("GET /scan-jobs/{id}", s.handleGetScanJob)
	mux.HandleFunc("GET /scan-results", s.handleGetScanResults)
	mux.HandleFunc("GET /inventory/{id}", s.handleGetInventoryByID)
	mux.HandleFunc("POST /v1/ingest/conversations", s.handleIngestConversation)

	if s.Ingest != nil {
		s.Ingest.AgentAuthenticator = s.authenticateAgentToken
	}
	mw := NewMiddleware(50, 100, s.middlewareOptionsFromEnv())
	handler := mw.SecureHeaders(mw.CORS(mw.Recoverer(mw.Logger(mw.RateLimit(mw.Authenticate(mw.LimitWriteBody(mux)))))))

	log.Println("Backend running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

func (s *Server) middlewareOptionsFromEnv() MiddlewareOptions {
	return MiddlewareOptions{
		APIKey:            os.Getenv("KARAXYS_API_KEY"),
		APIKeyAccountID:   os.Getenv("KARAXYS_API_KEY_ACCOUNT_ID"),
		APIKeyRole:        os.Getenv("KARAXYS_API_KEY_ROLE"),
		SessionAuth:       s.authenticateSessionToken,
		AllowedOrigins:    splitCSVEnv("KARAXYS_ALLOWED_ORIGINS", []string{"http://localhost:7000"}),
		MaxWriteBodyBytes: int64EnvDefault("KARAXYS_MAX_WRITE_BYTES", DefaultMaxWriteBodyBytes),
	}
}

func splitCSVEnv(key string, fallback []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	var values []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		return fallback
	}
	return values
}

func int64EnvDefault(key string, fallback int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func (s *Server) handleIngestConversation(w http.ResponseWriter, r *http.Request) {
	if s.Ingest == nil {
		http.Error(w, "Ingestion unavailable", http.StatusServiceUnavailable)
		return
	}
	s.Ingest.HandleConversation(w, r)
}

func (s *Server) handleGetInventory(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	pagination := db.Pagination{
		Page:      page,
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}
	var results *db.PaginatedResponse
	var err error
	if accountID, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		results, err = s.DB.GetInventoryForAccount(pagination, accountID)
	} else {
		results, err = s.DB.GetInventory(pagination)
	}
	if err != nil {
		http.Error(w, "Database Error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

type ScanRequest struct {
	InventoryID   string `json:"inventory_id"`
	TestType      string `json:"test_type"`
	AttackerToken string `json:"attacker_token"`
	AttackMethod  string `json:"attack_method"`
}

type ScanJobResponse struct {
	JobID        string `json:"job_id"`
	Status       string `json:"status"`
	InventoryID  string `json:"inventory_id"`
	TestType     string `json:"test_type"`
	Error        string `json:"error,omitempty"`
	ResultsCount int    `json:"results_count,omitempty"`
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, scanRoles...)
	if !ok {
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid JSON", 400)
		return
	}

	objID, err := primitive.ObjectIDFromHex(req.InventoryID)
	if err != nil {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "invalid inventory id")
		http.Error(w, "Invalid Inventory ID", 400)
		return
	}

	var target core.ApiInventory
	filter := bson.M{"_id": objID}
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			s.auditScanCreate(r, "", req, core.AuditStatusFailure, "invalid account")
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		filter["tenant_id"] = principal.AccountID
	}
	err = s.DB.Client.Database(s.DBName).Collection("api_inventory").FindOne(context.TODO(), filter).Decode(&target)
	if err != nil {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "endpoint not found")
		http.Error(w, "Endpoint Not Found", 404)
		return
	}

	if target.BaseURL == "" {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "target base url missing")
		http.Error(w, "Target BaseURL missing in inventory. Re-capture traffic.", 400)
		return
	}

	config, err := scanplan.BuildScanConfig(
		target.BaseURL,
		&target,
		req.AttackerToken,
		req.AttackMethod,
		req.TestType,
	)
	if err != nil {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "scan config error")
		http.Error(w, "Config Error: "+err.Error(), http.StatusBadRequest)
		return
	}

	jobID := primitive.NewObjectID()
	if err := s.externalizeScanAuthSecret(jobID, &config); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, scansecrets.ErrSecretKeyMissing) {
			status = http.StatusServiceUnavailable
		}
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "scan secret setup failed")
		http.Error(w, "Scan secret setup failed: "+err.Error(), status)
		return
	}

	job, err := s.DB.CreateScanJob(core.ScanJob{
		ID:           jobID,
		TenantID:     target.TenantID,
		ProjectID:    target.ProjectID,
		InventoryID:  target.ID,
		Status:       core.ScanJobStatusQueued,
		TestType:     req.TestType,
		AttackMethod: req.AttackMethod,
		Config:       config,
	})
	if err != nil {
		if config.AuthSecretRef != "" {
			s.deleteScanSecret(config.AuthSecretRef)
		}
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "failed to enqueue scan job")
		http.Error(w, "Failed to enqueue scan job", http.StatusInternalServerError)
		return
	}

	s.auditScanCreate(r, job.ID.Hex(), req, core.AuditStatusSuccess, "")
	log.Printf("Scan queued: job=%s test=%s target=%s", job.ID.Hex(), req.TestType, target.PathPattern)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ScanJobResponse{
		JobID:        job.ID.Hex(),
		Status:       job.Status,
		InventoryID:  target.ID.Hex(),
		TestType:     job.TestType,
		ResultsCount: job.ResultsCount,
	})
}

func (s *Server) auditScanCreate(r *http.Request, jobID string, req ScanRequest, status string, message string) {
	if s == nil || s.DB == nil {
		return
	}
	actorID := SubjectFromContext(r.Context())
	actorType := core.AuditActorAPIKey
	if principal, ok := PrincipalFromContext(r.Context()); ok && principal.ActorType != "" {
		actorType = principal.ActorType
		if principal.UserID != "" {
			actorID = principal.UserID
		}
	}
	if actorID == "" {
		actorID = "unknown"
	}
	if err := s.DB.SaveAuditLog(core.AuditLog{
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       core.AuditActionScanCreate,
		ResourceType: "scan_job",
		ResourceID:   jobID,
		Status:       status,
		RemoteAddr:   clientID(r),
		Message:      message,
		Metadata: map[string]string{
			"inventory_id":  req.InventoryID,
			"test_type":     req.TestType,
			"attack_method": req.AttackMethod,
		},
	}); err != nil {
		log.Printf("Failed to audit scan creation: %v", err)
	}
}

func (s *Server) externalizeScanAuthSecret(jobID primitive.ObjectID, config *core.ScanConfig) error {
	if config == nil || config.ManualAuth == "" {
		return nil
	}
	protector, err := scansecrets.FromEnv()
	if err != nil {
		return err
	}
	nonce, ciphertext, err := protector.Encrypt(config.ManualAuth)
	if err != nil {
		return fmt.Errorf("encrypt scan auth secret: %w", err)
	}
	secret, err := s.DB.SaveScanSecret(core.ScanSecret{
		JobID:      jobID,
		Purpose:    core.ScanSecretPurposeAuth,
		KeyID:      protector.KeyID(),
		Nonce:      nonce,
		Ciphertext: ciphertext,
		ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
	})
	if err != nil {
		return fmt.Errorf("persist scan auth secret: %w", err)
	}
	config.AuthSecretRef = secret.ID.Hex()
	config.ManualAuth = ""
	return nil
}

func (s *Server) deleteScanSecret(ref string) {
	id, err := primitive.ObjectIDFromHex(ref)
	if err != nil {
		return
	}
	if err := s.DB.DeleteScanSecret(id); err != nil {
		log.Printf("Failed to cleanup scan secret ref=%s: %v", ref, err)
	}
}

func (s *Server) handleGetScanJob(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	objID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid scan job ID", http.StatusBadRequest)
		return
	}
	job, err := s.DB.GetScanJob(objID)
	if err != nil {
		http.Error(w, "Scan Job Not Found", http.StatusNotFound)
		return
	}
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		if job.TenantID != principal.AccountID {
			http.Error(w, "Scan Job Not Found", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ScanJobResponse{
		JobID:        job.ID.Hex(),
		Status:       job.Status,
		InventoryID:  job.InventoryID.Hex(),
		TestType:     job.TestType,
		Error:        job.Error,
		ResultsCount: job.ResultsCount,
	})
}

func (s *Server) handleGetScanResults(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	inventoryIDStr := r.URL.Query().Get("inventory_id")
	jobIDStr := r.URL.Query().Get("job_id")

	var inventoryID *primitive.ObjectID
	if inventoryIDStr != "" {
		objID, err := primitive.ObjectIDFromHex(inventoryIDStr)
		if err != nil {
			http.Error(w, "Invalid inventory_id", http.StatusBadRequest)
			return
		}
		inventoryID = &objID
	}
	var jobID *primitive.ObjectID
	if jobIDStr != "" {
		objID, err := primitive.ObjectIDFromHex(jobIDStr)
		if err != nil {
			http.Error(w, "Invalid job_id", http.StatusBadRequest)
			return
		}
		jobID = &objID
	}

	pagination := db.Pagination{
		Page:      page,
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}
	var results *db.PaginatedResponse
	var err error
	if accountID, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		results, err = s.DB.GetScanResultsForAccount(pagination, inventoryID, jobID, accountID)
	} else {
		results, err = s.DB.GetScanResults(pagination, inventoryID, jobID)
	}
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleGetInventoryByID(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	objID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", 400)
		return
	}
	var target core.ApiInventory
	filter := bson.M{"_id": objID}
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		filter["tenant_id"] = principal.AccountID
	}
	err = s.DB.Client.Database(s.DBName).Collection("api_inventory").FindOne(context.TODO(), filter).Decode(&target)
	if err != nil {
		http.Error(w, "Endpoint Not Found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(target)
}
