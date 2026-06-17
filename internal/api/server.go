package api

import (
	"context"
	"encoding/json"
	"karaxys_backend/internal/analyzer"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/ingest"
	"karaxys_backend/internal/scanplan"
	"log"
	"net/http"
	"os"
	"strconv"

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
	mux.HandleFunc("GET /inventory", s.handleGetInventory)
	mux.HandleFunc("POST /scan", s.handleTriggerScan)
	mux.HandleFunc("GET /scan-jobs/{id}", s.handleGetScanJob)
	mux.HandleFunc("GET /scan-results", s.handleGetScanResults)
	mux.HandleFunc("GET /inventory/{id}", s.handleGetInventoryByID)
	mux.HandleFunc("POST /v1/ingest/conversations", s.handleIngestConversation)

	mw := NewMiddleware(50, 100)
	handler := mw.CORS(mw.Recoverer(mw.Logger(mw.RateLimit(mw.Authenticate(mux)))))

	log.Println("Backend running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

func (s *Server) handleIngestConversation(w http.ResponseWriter, r *http.Request) {
	if s.Ingest == nil {
		http.Error(w, "Ingestion unavailable", http.StatusServiceUnavailable)
		return
	}
	s.Ingest.HandleConversation(w, r)
}

func (s *Server) handleGetInventory(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
	results, err := s.DB.GetInventory(db.Pagination{
		Page:      page,
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	})
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
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	objID, err := primitive.ObjectIDFromHex(req.InventoryID)
	if err != nil {
		http.Error(w, "Invalid Inventory ID", 400)
		return
	}

	var target core.ApiInventory
	err = s.DB.Client.Database(s.DBName).Collection("api_inventory").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&target)
	if err != nil {
		http.Error(w, "Endpoint Not Found", 404)
		return
	}

	if target.BaseURL == "" {
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
		http.Error(w, "Config Error: "+err.Error(), http.StatusBadRequest)
		return
	}

	job, err := s.DB.CreateScanJob(core.ScanJob{
		InventoryID:  target.ID,
		Status:       core.ScanJobStatusQueued,
		TestType:     req.TestType,
		AttackMethod: req.AttackMethod,
		Config:       config,
	})
	if err != nil {
		http.Error(w, "Failed to enqueue scan job", http.StatusInternalServerError)
		return
	}

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

func (s *Server) handleGetScanJob(w http.ResponseWriter, r *http.Request) {
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

	results, err := s.DB.GetScanResults(db.Pagination{
		Page:      page,
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}, inventoryID, jobID)
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleGetInventoryByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	objID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", 400)
		return
	}
	var target core.ApiInventory
	err = s.DB.Client.Database(s.DBName).Collection("api_inventory").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&target)
	if err != nil {
		http.Error(w, "Endpoint Not Found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(target)
}
