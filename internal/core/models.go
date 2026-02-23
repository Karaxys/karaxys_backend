package core
import( 
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)
type TrafficLog struct{
	ID		primitive.ObjectID `bson:"_id,omitempty"`
	CreatedAt  time.Time      `bson:"created_at"`
	Method	  string	   `bson:"method"`
	URL       string     `bson:"url"`
	Host	  string     `bson:"host"`
	Path	  string     `bson:"path"`
	ReqHeaders map[string][]string `bson:"req_headers"`
	ReqBody   string	 `bson:"req_body"`
	RespStatus string	 `bson:"resp_status"`
	RespBody  string	 `bson:"resp_body"`
	Analyzed   bool       `bson:"analyzed"`
	IsScanned  bool       `bson:"is_scanned"`
	Tags	   []string   `bson:"tags"`
}

type ApiInventory struct {
	ID             primitive.ObjectID  `bson:"_id,omitempty"`
	Method         string              `bson:"method"`
	BaseURL        string              `bson:"base_url"`
	PathPattern    string              `bson:"path_pattern"`
	OriginalPath   string              `bson:"original_path"`	
	SensitiveData  []string            `bson:"sensitive_data"`
	RiskLevel      string              `bson:"risk_level"`
	SchemaReq      map[string]string   `bson:"schema_req"` 
	SampleHeaders  map[string][]string `bson:"sample_headers"`
	ParamValues    map[string][]string `bson:"param_values"`
	SampleReqBody  string              `bson:"sample_req_body"`
	SampleRespBody string              `bson:"sample_resp_body"`	
	CreatedAt      time.Time           `bson:"created_at"`
	UpdatedAt      time.Time           `bson:"updated_at"`
}

type ScanResult struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	InventoryID    primitive.ObjectID `bson:"inventory_id"`	
	TestType       string             `bson:"test_type"`
	Vulnerable     bool               `bson:"vulnerable"`
	Severity       string             `bson:"severity"`
	Description    string             `bson:"description"`
	Proof          string             `bson:"proof"`
	ResponseStatus int                `bson:"response_status"`
	ResponseBody   string             `bson:"response_body"`	
	CreatedAt      time.Time          `bson:"created_at"`
}