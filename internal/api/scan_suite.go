package api

import (
	"context"
	"encoding/json"
	"errors"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/scancontrol"
	"karaxys_backend/internal/scanner"
	"karaxys_backend/internal/scanplan"
	"karaxys_backend/internal/scanpolicy"
	"log"
	"net/http"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ScanSuiteRequest launches a batch of scan jobs against one endpoint. Test-type
// selection precedence: explicit TestTypes, then a named Suite preset, then all
// test types applicable to the endpoint. Every selection is intersected with
// applicability so no job is created that the endpoint cannot exercise.
type ScanSuiteRequest struct {
	InventoryID    string            `json:"inventory_id"`
	Suite          string            `json:"suite,omitempty"`
	TestTypes      []string          `json:"test_types,omitempty"`
	AttackerToken  string            `json:"attacker_token"`
	AuthContexts   map[string]string `json:"auth_contexts,omitempty"`
	AttackMethod   string            `json:"attack_method"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

type ScanSuiteResponse struct {
	SuiteID   string            `json:"suite_id"`
	Suite     string            `json:"suite,omitempty"`
	JobCount  int               `json:"job_count"`
	TestTypes []string          `json:"test_types"`
	Skipped   []string          `json:"skipped,omitempty"`
	Jobs      []ScanJobResponse `json:"jobs"`
}

type ScanSuiteStatusResponse struct {
	SuiteID       string            `json:"suite_id"`
	InventoryID   string            `json:"inventory_id,omitempty"`
	JobCount      int               `json:"job_count"`
	StatusCounts  map[string]int    `json:"status_counts"`
	TotalFindings int               `json:"total_findings"`
	Completed     bool              `json:"completed"`
	Jobs          []ScanJobResponse `json:"jobs"`
}

func (s *Server) handleListSuitePresets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoles(w, r, readRoles...); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": scanner.SuitePresets()})
}

func (s *Server) handleTriggerSuite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, scanRoles...)
	if !ok {
		return
	}
	var req ScanSuiteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(req.InventoryID)
	if err != nil {
		http.Error(w, "Invalid Inventory ID", http.StatusBadRequest)
		return
	}

	filter := bson.M{"_id": objID}
	if _, scoped, parseErr := scopedAccountID(principal); scoped {
		if parseErr != nil {
			http.Error(w, "Invalid account", http.StatusUnauthorized)
			return
		}
		filter["tenant_id"] = principal.AccountID
	}
	var target core.ApiInventory
	if err := s.DB.Client.Database(s.DBName).Collection("api_inventory").FindOne(context.TODO(), filter).Decode(&target); err != nil {
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
	timeoutSeconds, err := normalizeScanTimeout(req.TimeoutSeconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target = s.applyLatestTrafficSample(target)

	registry := scanner.DefaultTemplateRegistry()
	applicable := scanplan.ApplicableTestTypes(registry, &target, req.AuthContexts, req.AttackerToken)

	selected, skipped, err := selectSuiteTestTypes(registry, req, applicable)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(selected) == 0 {
		http.Error(w, "No applicable test types for this endpoint and selection", http.StatusBadRequest)
		return
	}

	suiteID := primitive.NewObjectID()
	jobs := make([]ScanJobResponse, 0, len(selected))
	for _, testType := range selected {
		jobResp, err := s.enqueueSuiteJob(r.Context(), target, suiteID, req, testType, timeoutSeconds)
		if err != nil {
			log.Printf("Suite job build failed suite=%s test=%s: %v", suiteID.Hex(), testType, err)
			skipped = append(skipped, testType)
			continue
		}
		jobs = append(jobs, jobResp)
	}
	if len(jobs) == 0 {
		http.Error(w, "Failed to enqueue any suite jobs", http.StatusInternalServerError)
		return
	}

	suiteName := strings.ToUpper(strings.TrimSpace(req.Suite))
	s.auditScanCreate(r, suiteID.Hex(), ScanRequest{InventoryID: req.InventoryID, TestType: "SUITE:" + suiteName}, core.AuditStatusSuccess, "")
	log.Printf("Suite queued: suite=%s inventory=%s jobs=%d preset=%s", suiteID.Hex(), target.PathPattern, len(jobs), suiteName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ScanSuiteResponse{
		SuiteID:   suiteID.Hex(),
		Suite:     suiteName,
		JobCount:  len(jobs),
		TestTypes: selected,
		Skipped:   skipped,
		Jobs:      jobs,
	})
}

// selectSuiteTestTypes resolves the requested selection against what the
// endpoint can actually exercise. Explicit test types win, then a named preset,
// then everything applicable. The skipped list reports requested-but-inapplicable
// types so the caller can surface why they were dropped.
func selectSuiteTestTypes(registry *scanner.TemplateRegistry, req ScanSuiteRequest, applicable []string) (selected []string, skipped []string, err error) {
	if len(req.TestTypes) > 0 {
		requested := registry.FilterRegistered(req.TestTypes)
		selected, skipped = intersectTestTypes(requested, applicable)
		return selected, skipped, nil
	}
	suiteID := strings.ToUpper(strings.TrimSpace(req.Suite))
	if suiteID != "" && suiteID != "FULL" {
		preset, ok := scanner.LookupSuitePreset(suiteID)
		if !ok {
			return nil, nil, errors.New("unknown suite preset")
		}
		members := registry.FilterRegistered(preset.TestTypes)
		selected, skipped = intersectTestTypes(members, applicable)
		return selected, skipped, nil
	}
	return applicable, nil, nil
}

func intersectTestTypes(requested []string, applicable []string) (selected []string, skipped []string) {
	applicableSet := make(map[string]bool, len(applicable))
	for _, testType := range applicable {
		applicableSet[testType] = true
	}
	seen := make(map[string]bool, len(requested))
	for _, testType := range requested {
		testType = strings.TrimSpace(testType)
		if testType == "" || seen[testType] {
			continue
		}
		seen[testType] = true
		if applicableSet[testType] {
			selected = append(selected, testType)
		} else {
			skipped = append(skipped, testType)
		}
	}
	return selected, skipped
}

func (s *Server) enqueueSuiteJob(ctx context.Context, target core.ApiInventory, suiteID primitive.ObjectID, req ScanSuiteRequest, testType string, timeoutSeconds int) (ScanJobResponse, error) {
	config, err := scanplan.BuildScanConfigWithAuthContexts(
		target.BaseURL,
		&target,
		req.AuthContexts,
		req.AttackerToken,
		req.AttackMethod,
		testType,
	)
	if err != nil {
		return ScanJobResponse{}, err
	}
	config = scancontrol.ApplyExecutionLimits(config, scancontrol.LoadConfigFromEnv())

	jobID := primitive.NewObjectID()
	if err := s.externalizeScanAuthSecret(jobID, &config); err != nil {
		return ScanJobResponse{}, err
	}

	job, err := s.DB.CreateScanJob(core.ScanJob{
		ID:             jobID,
		TenantID:       target.TenantID,
		ProjectID:      target.ProjectID,
		InventoryID:    target.ID,
		SuiteID:        suiteID,
		Status:         core.ScanJobStatusQueued,
		TestType:       testType,
		AttackMethod:   req.AttackMethod,
		Config:         config,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		if config.AuthSecretRef != "" {
			s.deleteScanSecret(config.AuthSecretRef)
		}
		return ScanJobResponse{}, err
	}

	if err := s.publishScanJobQueued(ctx, job); err != nil {
		log.Printf("Failed to publish suite scan job job=%s: %v", job.ID.Hex(), err)
	}
	return scanJobResponse(&job), nil
}

func (s *Server) handleGetSuite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireRoles(w, r, readRoles...)
	if !ok {
		return
	}
	suiteID, err := primitive.ObjectIDFromHex(r.PathValue("id"))
	if err != nil {
		http.Error(w, "Invalid suite id", http.StatusBadRequest)
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
	jobs, err := s.DB.GetScanJobsBySuite(suiteID, tenantID)
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	if len(jobs) == 0 {
		http.Error(w, "Suite Not Found", http.StatusNotFound)
		return
	}

	statusCounts := map[string]int{}
	totalFindings := 0
	completed := true
	jobResponses := make([]ScanJobResponse, 0, len(jobs))
	for i := range jobs {
		job := jobs[i]
		statusCounts[job.Status]++
		totalFindings += job.ResultsCount
		if !isTerminalScanStatus(job.Status) {
			completed = false
		}
		jobResponses = append(jobResponses, scanJobResponse(&job))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ScanSuiteStatusResponse{
		SuiteID:       suiteID.Hex(),
		InventoryID:   jobs[0].InventoryID.Hex(),
		JobCount:      len(jobs),
		StatusCounts:  statusCounts,
		TotalFindings: totalFindings,
		Completed:     completed,
		Jobs:          jobResponses,
	})
}

func isTerminalScanStatus(status string) bool {
	switch status {
	case core.ScanJobStatusCompleted, core.ScanJobStatusFailed, core.ScanJobStatusCancelled, core.ScanJobStatusTimedOut:
		return true
	default:
		return false
	}
}
