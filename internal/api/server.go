package api
import(
	"context"
	"encoding/json"
	"fmt"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/scanner"
	"log"
	"net/http"
	"strconv"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Server struct {
	DB      *db.DB
	Scanner *scanner.Scanner
	DBName  string
}

func NewServer(db *db.DB, dbName string) *Server {
	return &Server{
		DB:      db,
		Scanner: scanner.NewScanner(),
		DBName:  dbName,
	}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /inventory", s.handleGetInventory)
	mux.HandleFunc("POST /scan", s.handleTriggerScan)
	mux.HandleFunc("GET /scan-results", s.handleGetScanResults)
	mux.HandleFunc("GET /inventory/{id}", s.handleGetInventoryByID)

	mw := NewMiddleware(50, 100)
	handler := mw.CORS(mw.Recoverer(mw.Logger(mw.RateLimit(mw.Authenticate(mux)))))

	log.Println("Backend running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
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

	config, err := scanner.BuildScanConfig(
		target.BaseURL,
		&target,
		req.AttackerToken,
		req.AttackMethod,
		req.TestType,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Config Error: %v", err), 400)
		return
	}

	log.Printf("Scan Triggered: %s on %s", req.TestType, target.PathPattern)
	results, err := s.Scanner.ExecuteScan(config)
	if err != nil {
		http.Error(w, fmt.Sprintf("Scan Failed: %v", err), 500)
		return
	}

	for _, res := range results {
		logEntry := core.ScanResult{
			InventoryID:    target.ID,
			TestType:       res.TestType,
			Vulnerable:     res.Vulnerable,
			Severity:       res.Severity,
			Description:    res.Description,
			Proof:          res.Proof,
			ResponseStatus: res.ResponseStatus,
			ResponseBody:   res.ResponseBody,
			CreatedAt:      time.Now(),
		}
		s.DB.SaveScanResult(logEntry)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleGetScanResults(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")
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

	results, err := s.DB.GetScanResults(db.Pagination{
		Page:      page,
		Limit:     limit,
		Offset:    offset,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}, inventoryID)
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