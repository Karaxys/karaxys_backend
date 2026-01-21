package api
import(
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/scanner"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Server struct{
	DB      *mongo.Database
	Scanner *scanner.Scanner
}

func NewServer(db *mongo.Database) *Server{
	return &Server{
		DB:      db,
		Scanner: scanner.NewScanner(),
	}
}

func enableCORS(next http.Handler) http.Handler{
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Start(){
	mux := http.NewServeMux()
	mux.HandleFunc("GET /inventory", s.handleGetInventory)
	mux.HandleFunc("POST /scan", s.handleTriggerScan)

	log.Println("Backend running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", enableCORS(mux)))
}

func (s *Server) handleGetInventory(w http.ResponseWriter, r *http.Request){
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := s.DB.Collection("api_inventory").Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var results []core.ApiInventory
	if err = cursor.All(ctx, &results); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

type ScanRequest struct{
	InventoryID   string `json:"inventory_id"`
	TestType      string `json:"test_type"`
	AttackerToken string `json:"attacker_token"`
	AttackMethod  string `json:"attack_method"`
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request){
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	objID, err := primitive.ObjectIDFromHex(req.InventoryID)
	if err != nil {
		http.Error(w, "Invalid Inventory ID", 400); return
	}

	var target core.ApiInventory
	err = s.DB.Collection("api_inventory").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&target)
	if err != nil {
		http.Error(w, "Endpoint Not Found", 404); return
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
	if err != nil{
		http.Error(w, fmt.Sprintf("Scan Failed: %v", err), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}