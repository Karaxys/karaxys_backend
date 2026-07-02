package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/coordination"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/queue"
	"karaxys_backend/internal/scancontrol"
	"karaxys_backend/internal/scanner"
	"karaxys_backend/internal/scanplan"
	"karaxys_backend/internal/scanpolicy"
	"karaxys_backend/internal/security/scansecrets"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Server struct {
	DB            *db.DB
	DBName        string
	Ingest        *ingest.Service
	queueProducer queue.Producer
}

func NewServer(db *db.DB, dbName string, processors ...*analyzer.Processor) *Server {
	var processor *analyzer.Processor
	if len(processors) > 0 {
		processor = processors[0]
	}
	if processor == nil {
		processor = analyzer.NewProcessor(db.Client.Database(dbName))
	}

	server := &Server{
		DB:     db,
		DBName: dbName,
		Ingest: ingest.NewService(db, processor, os.Getenv("KARAXYS_AGENT_TOKEN")),
	}
	server.configureIngestQueuePublisherFromEnv()
	return server
}

func (s *Server) Start() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.StartWithContext(ctx, ":8081"); err != nil {
		log.Fatal(err)
	}
}

// registerRoutes wires every HTTP route onto mux. Kept separate from
// StartWithContext so route registration can be exercised in tests (Go's
// ServeMux panics on conflicting wildcard patterns at registration time).
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/signup", s.handleSignup)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/me", s.handleMe)
	mux.HandleFunc("GET /auth/oauth/{provider}", s.handleOAuthStart)
	mux.HandleFunc("GET /auth/oauth/{provider}/callback", s.handleOAuthCallback)
	mux.HandleFunc("GET /quick-start", s.handleQuickStartState)
	mux.HandleFunc("POST /api/fetchQuickStartPageState", s.handleQuickStartState)
	mux.HandleFunc("GET /data-sources", s.handleListDataSources)
	mux.HandleFunc("POST /data-sources", s.handleCreateDataSource)
	mux.HandleFunc("DELETE /data-sources/{id}", s.handleDeleteDataSource)
	mux.HandleFunc("POST /agent-enrollments", s.handleCreateAgentEnrollment)
	mux.HandleFunc("POST /agents/register", s.handleRegisterAgent)
	mux.HandleFunc("POST /agents/heartbeat", s.handleAgentHeartbeat)
	mux.HandleFunc("GET /agents/config", s.handleAgentConfig)
	mux.HandleFunc("GET /settings/security", s.handleGetSecuritySettings)
	mux.HandleFunc("PUT /settings/security", s.handleUpdateSecuritySettings)
	mux.HandleFunc("GET /inventory", s.handleGetInventory)
	mux.HandleFunc("GET /scan/test-types", s.handleListTestTypes)
	mux.HandleFunc("GET /v1/scan/test-types", s.handleListTestTypes)
	mux.HandleFunc("GET /scan/suite-presets", s.handleListSuitePresets)
	mux.HandleFunc("GET /v1/scan/suite-presets", s.handleListSuitePresets)
	mux.HandleFunc("POST /scan/suite", s.handleTriggerSuite)
	mux.HandleFunc("POST /v1/scans/suite", s.handleTriggerSuite)
	mux.HandleFunc("GET /scan/suites/{id}", s.handleGetSuite)
	mux.HandleFunc("GET /v1/scan/suites/{id}", s.handleGetSuite)
	mux.HandleFunc("POST /scan", s.handleTriggerScan)
	mux.HandleFunc("GET /scan-jobs/{id}", s.handleGetScanJob)
	mux.HandleFunc("GET /scan-results", s.handleGetScanResults)
	mux.HandleFunc("POST /v1/scans", s.handleTriggerScan)
	mux.HandleFunc("GET /v1/scans", s.handleListScanJobs)
	mux.HandleFunc("GET /v1/scans/{id}", s.handleGetScanJob)
	mux.HandleFunc("POST /v1/scans/{id}/cancel", s.handleCancelScanJob)
	mux.HandleFunc("POST /v1/scans/{id}/rerun", s.handleRerunScanJob)
	mux.HandleFunc("GET /v1/scans/{id}/events", s.handleGetScanProgressEvents)
	mux.HandleFunc("GET /issues", s.handleListIssues)
	mux.HandleFunc("GET /v1/issues", s.handleListIssues)
	mux.HandleFunc("PATCH /v1/issues/{id}", s.handleUpdateIssue)
	mux.HandleFunc("GET /inventory/{id}", s.handleGetInventoryByID)
	mux.HandleFunc("GET /v1/agents", s.handleListAgents)
	mux.HandleFunc("GET /v1/agent-enrollments", s.handleListAgentEnrollments)
	mux.HandleFunc("GET /v1/metrics/summary", s.handleMetricsSummary)
	mux.HandleFunc("POST /v1/ingest/conversations", s.handleIngestConversation)
	// Akto-style account-token ingest — supports single and batched conversations.
	mux.HandleFunc("POST /ingest", s.handleAccountIngest)
	// Ingest token management — admin only, requires dashboard session.
	mux.HandleFunc("GET /account/ingest-token", s.handleGetIngestToken)
	mux.HandleFunc("POST /account/ingest-token/rotate", s.handleRotateIngestToken)
	// Versioned data-source aliases for forward-compatibility.
	mux.HandleFunc("GET /v1/data-sources", s.handleListDataSources)
	mux.HandleFunc("POST /v1/data-sources", s.handleCreateDataSource)
	mux.HandleFunc("DELETE /v1/data-sources/{id}", s.handleDeleteDataSource)
}

func (s *Server) StartWithContext(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	if s.Ingest != nil {
		s.Ingest.AgentAuthenticator = s.authenticateAgentToken
	}
	middlewareOptions := s.middlewareOptionsFromEnv()
	redisRuntime, err := coordination.NewRedisRuntimeFromEnv()
	if err != nil {
		if config.IsProduction() {
			log.Fatalf("Redis/Valkey coordination is required in production: %v", err)
		}
		log.Printf("Redis/Valkey coordination disabled: %v", err)
	}
	if redisRuntime != nil {
		defer redisRuntime.Close()
		middlewareOptions.RateLimiter = redisRuntime.RateLimiter
		log.Printf("Redis/Valkey distributed rate limiter enabled prefix=%s", redisRuntime.KeyPrefix)
	}
	mw := NewMiddleware(50, 100, middlewareOptions)
	handler := mw.SecureHeaders(mw.CORS(mw.Recoverer(mw.Logger(mw.RateLimit(mw.Authenticate(mw.LimitWriteBody(mux)))))))

	if strings.TrimSpace(addr) == "" {
		addr = ":8081"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer s.Close()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Backend running on http://localhost%s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func (s *Server) Close() {
	if s == nil || s.queueProducer == nil {
		return
	}
	if err := s.queueProducer.Close(); err != nil {
		log.Printf("Conversation queue producer close error: %v", err)
	}
	s.queueProducer = nil
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

func (s *Server) configureIngestQueuePublisherFromEnv() {
	if s == nil || s.Ingest == nil || !queuePublishingEnabled() {
		return
	}
	cfg := queue.LoadKafkaConfigFromEnv([]string{queue.TopicHTTPConversations})
	producer, err := queue.NewKafkaProducer(cfg)
	if err != nil {
		if config.IsProduction() {
			log.Fatalf("Kafka-compatible conversation queue is required in production: %v", err)
		}
		log.Printf("Conversation queue publishing disabled: %v", err)
		return
	}
	s.queueProducer = producer
	s.Ingest.Publisher = ingest.NewQueuePublisher(producer)
	log.Printf("Conversation queue publishing enabled brokers=%s topic=%s", strings.Join(cfg.Brokers, ","), queue.TopicHTTPConversations)
}

func queuePublishingEnabled() bool {
	if config.IsProduction() {
		return true
	}
	raw := strings.TrimSpace(os.Getenv("KARAXYS_QUEUE_ENABLED"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("Invalid KARAXYS_QUEUE_ENABLED value %q; queue publishing disabled", raw)
		return false
	}
	return enabled
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
	InventoryID    string            `json:"inventory_id"`
	TestType       string            `json:"test_type"`
	AttackerToken  string            `json:"attacker_token"`
	AuthContexts   map[string]string `json:"auth_contexts,omitempty"`
	AttackMethod   string            `json:"attack_method"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

type ScanRerunRequest struct {
	AttackerToken  string            `json:"attacker_token"`
	AuthContexts   map[string]string `json:"auth_contexts,omitempty"`
	AttackMethod   string            `json:"attack_method"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

type ScanJobResponse struct {
	JobID          string `json:"job_id"`
	Status         string `json:"status"`
	InventoryID    string `json:"inventory_id"`
	RerunOfJobID   string `json:"rerun_of_job_id,omitempty"`
	TestType       string `json:"test_type"`
	Error          string `json:"error,omitempty"`
	ResultsCount   int    `json:"results_count,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	StartedAt      string `json:"started_at,omitempty"`
	DeadlineAt     string `json:"deadline_at,omitempty"`
	CompletedAt    string `json:"completed_at,omitempty"`
}

type testTypeResponse struct {
	TestType             string `json:"test_type"`
	Category             string `json:"category"`
	Severity             string `json:"severity"`
	Description          string `json:"description,omitempty"`
	RequiresAttackerAuth bool   `json:"requires_attacker_auth"`
}

// handleListTestTypes exposes the scanner's registered test types (including
// auto-discovered community templates) so the dashboard can build its scan
// options from the live registry instead of a hardcoded list.
func (s *Server) handleListTestTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoles(w, r, readRoles...); !ok {
		return
	}
	metas := scanner.DefaultTemplateRegistry().ListMetadata()
	out := make([]testTypeResponse, 0, len(metas))
	for _, meta := range metas {
		out = append(out, testTypeResponse{
			TestType:             meta.TestType,
			Category:             meta.Category,
			Severity:             meta.Severity,
			Description:          meta.Description,
			RequiresAttackerAuth: meta.RequiresAttackerAuth,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": out})
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
	if err := scanpolicy.LoadTargetPolicyFromEnv().ValidateTargetURL(r.Context(), target.BaseURL); err != nil {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "target blocked by scan policy")
		http.Error(w, "Target blocked by scan policy: "+err.Error(), scanPolicyHTTPStatus(err))
		return
	}

	timeoutSeconds, err := normalizeScanTimeout(req.TimeoutSeconds)
	if err != nil {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "invalid scan timeout")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target = s.applyLatestTrafficSample(target)

	config, err := scanplan.BuildScanConfigWithAuthContexts(
		target.BaseURL,
		&target,
		req.AuthContexts,
		req.AttackerToken,
		req.AttackMethod,
		req.TestType,
	)
	if err != nil {
		s.auditScanCreate(r, "", req, core.AuditStatusFailure, "scan config error")
		http.Error(w, "Config Error: "+err.Error(), http.StatusBadRequest)
		return
	}
	config = scancontrol.ApplyExecutionLimits(config, scancontrol.LoadConfigFromEnv())

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
		ID:             jobID,
		TenantID:       target.TenantID,
		ProjectID:      target.ProjectID,
		InventoryID:    target.ID,
		Status:         core.ScanJobStatusQueued,
		TestType:       req.TestType,
		AttackMethod:   req.AttackMethod,
		Config:         config,
		TimeoutSeconds: timeoutSeconds,
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
	if err := s.publishScanJobQueued(r.Context(), job); err != nil {
		log.Printf("Failed to publish scan job event job=%s: %v", job.ID.Hex(), err)
	}
	log.Printf("Scan queued: job=%s test=%s target=%s", job.ID.Hex(), req.TestType, target.PathPattern)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ScanJobResponse{
		JobID:          job.ID.Hex(),
		Status:         job.Status,
		InventoryID:    target.ID.Hex(),
		RerunOfJobID:   objectIDHexOrEmpty(job.RerunOfJobID),
		TestType:       job.TestType,
		ResultsCount:   job.ResultsCount,
		TimeoutSeconds: job.TimeoutSeconds,
		CreatedAt:      formatOptionalTime(job.CreatedAt),
	})
}

func normalizeScanTimeout(timeoutSeconds int) (int, error) {
	if timeoutSeconds == 0 {
		return core.DefaultScanTimeoutSeconds, nil
	}
	if timeoutSeconds < 1 || timeoutSeconds > core.MaxScanTimeoutSeconds {
		return 0, fmt.Errorf("timeout_seconds must be between 1 and %d", core.MaxScanTimeoutSeconds)
	}
	return timeoutSeconds, nil
}

func scanPolicyHTTPStatus(err error) int {
	switch {
	case errors.Is(err, scanpolicy.ErrTargetDenied), errors.Is(err, scanpolicy.ErrTargetNotAllowed), errors.Is(err, scanpolicy.ErrTargetPrivateNetwork), errors.Is(err, scanpolicy.ErrTargetMetadata):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
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
		JobID:          job.ID.Hex(),
		Status:         job.Status,
		InventoryID:    job.InventoryID.Hex(),
		RerunOfJobID:   objectIDHexOrEmpty(job.RerunOfJobID),
		TestType:       job.TestType,
		Error:          job.Error,
		ResultsCount:   job.ResultsCount,
		TimeoutSeconds: job.TimeoutSeconds,
		CreatedAt:      formatOptionalTime(job.CreatedAt),
		StartedAt:      formatOptionalTime(job.StartedAt),
		DeadlineAt:     formatOptionalTime(job.DeadlineAt),
		CompletedAt:    formatOptionalTime(job.CompletedAt),
	})
}

func (s *Server) handleCancelScanJob(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, scanRoles...)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	objID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid scan job ID", http.StatusBadRequest)
		return
	}
	tenantID := ""
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		tenantID = principal.AccountID
	}
	job, err := s.DB.CancelScanJob(objID, tenantID)
	if err != nil {
		if errors.Is(err, db.ErrScanJobNotCancellable) {
			http.Error(w, "Scan job is already terminal", http.StatusConflict)
			return
		}
		http.Error(w, "Scan Job Not Found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, scanJobResponse(job))
}

func (s *Server) handleRerunScanJob(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, scanRoles...)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	originalID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid scan job ID", http.StatusBadRequest)
		return
	}
	originalJob, err := s.DB.GetScanJob(originalID)
	if err != nil {
		http.Error(w, "Scan Job Not Found", http.StatusNotFound)
		return
	}
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		if originalJob.TenantID != principal.AccountID {
			http.Error(w, "Scan Job Not Found", http.StatusNotFound)
			return
		}
	}

	var req ScanRerunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var target core.ApiInventory
	filter := bson.M{"_id": originalJob.InventoryID}
	if originalJob.TenantID != "" {
		filter["tenant_id"] = originalJob.TenantID
	}
	if err := s.DB.Client.Database(s.DBName).Collection("api_inventory").FindOne(r.Context(), filter).Decode(&target); err != nil {
		http.Error(w, "Endpoint Not Found", http.StatusNotFound)
		return
	}
	if target.BaseURL == "" {
		http.Error(w, "Target BaseURL missing in inventory. Re-capture traffic.", http.StatusBadRequest)
		return
	}
	if err := scanpolicy.LoadTargetPolicyFromEnv().ValidateTargetURL(r.Context(), target.BaseURL); err != nil {
		http.Error(w, "Target blocked by scan policy: "+err.Error(), scanPolicyHTTPStatus(err))
		return
	}

	attackMethod := strings.TrimSpace(req.AttackMethod)
	if attackMethod == "" {
		attackMethod = originalJob.AttackMethod
	}
	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds == 0 {
		timeoutSeconds = originalJob.TimeoutSeconds
	}
	timeoutSeconds, err = normalizeScanTimeout(timeoutSeconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target = s.applyLatestTrafficSample(target)
	config, err := scanplan.BuildScanConfigWithAuthContexts(target.BaseURL, &target, req.AuthContexts, req.AttackerToken, attackMethod, originalJob.TestType)
	if err != nil {
		http.Error(w, "Config Error: "+err.Error(), http.StatusBadRequest)
		return
	}
	config = scancontrol.ApplyExecutionLimits(config, scancontrol.LoadConfigFromEnv())

	newJobID := primitive.NewObjectID()
	if err := s.externalizeScanAuthSecret(newJobID, &config); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, scansecrets.ErrSecretKeyMissing) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "Scan secret setup failed: "+err.Error(), status)
		return
	}
	job, err := s.DB.CreateScanJob(core.ScanJob{
		ID:             newJobID,
		TenantID:       target.TenantID,
		ProjectID:      target.ProjectID,
		InventoryID:    target.ID,
		RerunOfJobID:   originalJob.ID,
		Status:         core.ScanJobStatusQueued,
		TestType:       originalJob.TestType,
		AttackMethod:   attackMethod,
		Config:         config,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		if config.AuthSecretRef != "" {
			s.deleteScanSecret(config.AuthSecretRef)
		}
		http.Error(w, "Failed to enqueue scan rerun", http.StatusInternalServerError)
		return
	}
	auditReq := ScanRequest{
		InventoryID:    target.ID.Hex(),
		TestType:       originalJob.TestType,
		AttackMethod:   attackMethod,
		TimeoutSeconds: timeoutSeconds,
	}
	s.auditScanCreate(r, job.ID.Hex(), auditReq, core.AuditStatusSuccess, "scan rerun")
	if err := s.publishScanJobQueued(r.Context(), job); err != nil {
		log.Printf("Failed to publish scan rerun event job=%s: %v", job.ID.Hex(), err)
	}
	writeJSON(w, http.StatusAccepted, scanJobResponse(&job))
}

func (s *Server) publishScanJobQueued(ctx context.Context, job core.ScanJob) error {
	if s == nil || s.queueProducer == nil {
		return nil
	}
	key := queue.ScanJobIdempotencyKey(job.ID.Hex())
	if key == "" {
		return fmt.Errorf("scan job id is required")
	}
	event := queue.ScanJobEvent{
		SchemaVersion: queue.EventScanJobV1,
		JobID:         job.ID.Hex(),
		InventoryID:   job.InventoryID.Hex(),
		TenantID:      job.TenantID,
		ProjectID:     job.ProjectID,
		TestType:      job.TestType,
		Status:        job.Status,
		CreatedAt:     time.Now().UTC(),
	}
	envelope, err := queue.NewEnvelope(
		queue.EventScanJobV1,
		queue.PayloadScanJobQueuedV1,
		event,
		queue.WithEventID(key),
		queue.WithIdempotencyKey(key),
		queue.WithIdentity(job.TenantID, job.ProjectID, "", "active_scanner"),
	)
	if err != nil {
		return err
	}
	message, err := queue.EncodeEnvelope(queue.TopicScanJobs, key, envelope)
	if err != nil {
		return err
	}
	return s.queueProducer.Produce(ctx, message)
}

func (s *Server) handleGetScanProgressEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	jobID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid scan job ID", http.StatusBadRequest)
		return
	}
	job, err := s.DB.GetScanJob(jobID)
	if err != nil {
		http.Error(w, "Scan Job Not Found", http.StatusNotFound)
		return
	}
	tenantID := ""
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		if job.TenantID != principal.AccountID {
			http.Error(w, "Scan Job Not Found", http.StatusNotFound)
			return
		}
		tenantID = principal.AccountID
	}
	events, err := s.DB.GetScanProgressEvents(jobID, tenantID)
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": events})
}

func scanJobResponse(job *core.ScanJob) ScanJobResponse {
	if job == nil {
		return ScanJobResponse{}
	}
	return ScanJobResponse{
		JobID:          job.ID.Hex(),
		Status:         job.Status,
		InventoryID:    job.InventoryID.Hex(),
		RerunOfJobID:   objectIDHexOrEmpty(job.RerunOfJobID),
		TestType:       job.TestType,
		Error:          job.Error,
		ResultsCount:   job.ResultsCount,
		TimeoutSeconds: job.TimeoutSeconds,
		CreatedAt:      formatOptionalTime(job.CreatedAt),
		StartedAt:      formatOptionalTime(job.StartedAt),
		DeadlineAt:     formatOptionalTime(job.DeadlineAt),
		CompletedAt:    formatOptionalTime(job.CompletedAt),
	}
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02T15:04:05.000Z")
}

func objectIDHexOrEmpty(value primitive.ObjectID) string {
	if value.IsZero() {
		return ""
	}
	return value.Hex()
}

func (s *Server) applyLatestTrafficSample(target core.ApiInventory) core.ApiInventory {
	if s == nil || s.DB == nil {
		return target
	}
	sample, err := s.DB.ResolveLatestTrafficSample(target)
	if err != nil {
		log.Printf("Failed to resolve latest traffic sample inventory=%s: %v", target.ID.Hex(), err)
		return target
	}
	return db.ApplyTrafficSampleToInventory(target, sample)
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
	suiteIDStr := r.URL.Query().Get("suite_id")

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
	var suiteID *primitive.ObjectID
	if suiteIDStr != "" {
		objID, err := primitive.ObjectIDFromHex(suiteIDStr)
		if err != nil {
			http.Error(w, "Invalid suite_id", http.StatusBadRequest)
			return
		}
		suiteID = &objID
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
		results, err = s.DB.GetScanResultsForAccount(pagination, inventoryID, jobID, suiteID, accountID)
	} else {
		results, err = s.DB.GetScanResults(pagination, inventoryID, jobID, suiteID)
	}
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleListIssues(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")
	inventoryIDStr := r.URL.Query().Get("inventory_id")

	var inventoryID *primitive.ObjectID
	if inventoryIDStr != "" {
		objID, err := primitive.ObjectIDFromHex(inventoryIDStr)
		if err != nil {
			http.Error(w, "Invalid inventory_id", http.StatusBadRequest)
			return
		}
		inventoryID = &objID
	}

	tenantID := ""
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		tenantID = principal.AccountID
	}
	results, err := s.DB.GetIssues(db.Pagination{
		Page:      page,
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}, tenantID, status, severity, inventoryID)
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleListScanJobs(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	status := r.URL.Query().Get("status")
	inventoryIDStr := r.URL.Query().Get("inventory_id")

	var inventoryID *primitive.ObjectID
	if inventoryIDStr != "" {
		objID, err := primitive.ObjectIDFromHex(inventoryIDStr)
		if err != nil {
			http.Error(w, "Invalid inventory_id", http.StatusBadRequest)
			return
		}
		inventoryID = &objID
	}

	p := db.Pagination{Page: page, Limit: limit, Offset: offset, SortBy: sortBy, SortOrder: sortOrder}
	var results *db.PaginatedResponse
	var err error
	if accountID, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		results, err = s.DB.GetScanJobsForAccount(p, accountID, status, inventoryID)
	} else {
		results, err = s.DB.GetScanJobs(p, "", status, inventoryID)
	}
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleUpdateIssue(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, scanRoles...)
	if !ok {
		return
	}
	idStr := r.PathValue("id")
	objID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	validStatuses := map[string]bool{
		core.IssueStatusOpen:          true,
		core.IssueStatusAcceptedRisk:  true,
		core.IssueStatusFalsePositive: true,
		core.IssueStatusFixed:         true,
	}
	if !validStatuses[body.Status] {
		http.Error(w, "Invalid status. Must be one of: open, accepted_risk, false_positive, fixed", http.StatusBadRequest)
		return
	}
	tenantID := ""
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		tenantID = principal.AccountID
	}
	updated, err := s.DB.UpdateIssueStatus(objID, tenantID, body.Status)
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	if updated == nil {
		http.Error(w, "Issue not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, updated)
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

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	accountID, ok := requireAccountObjectID(w, principal)
	if !ok {
		return
	}
	agents, err := s.DB.ListAgentsForAccount(accountID)
	if err != nil {
		http.Error(w, "Failed to load agents", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": agents})
}

func (s *Server) handleListAgentEnrollments(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	accountID, ok := requireAccountObjectID(w, principal)
	if !ok {
		return
	}
	enrollments, err := s.DB.ListEnrollmentsForAccount(accountID)
	if err != nil {
		http.Error(w, "Failed to load enrollments", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": enrollments})
}

func (s *Server) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	accountID, ok := requireAccountObjectID(w, principal)
	if !ok {
		return
	}
	summary, err := s.DB.GetMetricsSummary(accountID)
	if err != nil {
		http.Error(w, "Failed to load metrics", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
