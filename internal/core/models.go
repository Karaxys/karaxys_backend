package core

import (
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

var ErrTrafficLogDropped = errors.New("traffic log dropped by retention policy")

type TrafficLog struct {
	ID            primitive.ObjectID  `bson:"_id,omitempty"`
	SchemaVersion string              `bson:"schema_version,omitempty" json:"schema_version,omitempty"`
	CaptureSource string              `bson:"capture_source,omitempty" json:"capture_source,omitempty"`
	CaptureMode   string              `bson:"capture_mode,omitempty" json:"capture_mode,omitempty"`
	AgentID       string              `bson:"agent_id,omitempty" json:"agent_id,omitempty"`
	CreatedAt     time.Time           `bson:"created_at"`
	Method        string              `bson:"method"`
	URL           string              `bson:"url"`
	Host          string              `bson:"host"`
	Path          string              `bson:"path"`
	ReqHeaders    map[string][]string `bson:"req_headers"`
	ReqBody       string              `bson:"req_body"`
	RespStatus    string              `bson:"resp_status"`
	RespBody      string              `bson:"resp_body"`
	Analyzed      bool                `bson:"analyzed"`
	IsScanned     bool                `bson:"is_scanned"`
	Tags          []string            `bson:"tags"`
}

type TrafficConversation struct {
	ID             primitive.ObjectID  `bson:"_id,omitempty" json:"id,omitempty"`
	ConversationID string              `bson:"conversation_id" json:"conversation_id"`
	SchemaVersion  string              `bson:"schema_version" json:"schema_version"`
	TenantID       string              `bson:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ProjectID      string              `bson:"project_id,omitempty" json:"project_id,omitempty"`
	AgentID        string              `bson:"agent_id,omitempty" json:"agent_id,omitempty"`
	CaptureSource  string              `bson:"capture_source" json:"capture_source"`
	CaptureMode    string              `bson:"capture_mode,omitempty" json:"capture_mode,omitempty"`
	CapturedAt     time.Time           `bson:"captured_at" json:"captured_at"`
	Method         string              `bson:"method" json:"method"`
	URL            string              `bson:"url" json:"url"`
	Host           string              `bson:"host" json:"host"`
	Path           string              `bson:"path" json:"path"`
	ReqHeaders     map[string][]string `bson:"req_headers,omitempty" json:"req_headers,omitempty"`
	ReqBody        string              `bson:"req_body,omitempty" json:"req_body,omitempty"`
	RespStatus     string              `bson:"resp_status" json:"resp_status"`
	RespStatusCode int                 `bson:"resp_status_code,omitempty" json:"resp_status_code,omitempty"`
	RespHeaders    map[string][]string `bson:"resp_headers,omitempty" json:"resp_headers,omitempty"`
	RespBody       string              `bson:"resp_body,omitempty" json:"resp_body,omitempty"`
	CreatedAt      time.Time           `bson:"created_at" json:"created_at"`
}

type IngestionLog struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	Status         string             `bson:"status" json:"status"`
	SchemaVersion  string             `bson:"schema_version,omitempty" json:"schema_version,omitempty"`
	CaptureSource  string             `bson:"capture_source,omitempty" json:"capture_source,omitempty"`
	AgentID        string             `bson:"agent_id,omitempty" json:"agent_id,omitempty"`
	ConversationID string             `bson:"conversation_id,omitempty" json:"conversation_id,omitempty"`
	Method         string             `bson:"method,omitempty" json:"method,omitempty"`
	Host           string             `bson:"host,omitempty" json:"host,omitempty"`
	Path           string             `bson:"path,omitempty" json:"path,omitempty"`
	Message        string             `bson:"message,omitempty" json:"message,omitempty"`
}

type IngestDeadLetter struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	Reason         string             `bson:"reason" json:"reason"`
	SchemaVersion  string             `bson:"schema_version,omitempty" json:"schema_version,omitempty"`
	AgentID        string             `bson:"agent_id,omitempty" json:"agent_id,omitempty"`
	RemoteAddr     string             `bson:"remote_addr,omitempty" json:"remote_addr,omitempty"`
	PayloadExcerpt string             `bson:"payload_excerpt,omitempty" json:"payload_excerpt,omitempty"`
}

const (
	AuditActorAPIKey      = "api_key"
	AuditActionScanCreate = "scan.create"
	AuditStatusSuccess    = "success"
	AuditStatusFailure    = "failure"
)

type AuditLog struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	ActorType    string             `bson:"actor_type" json:"actor_type"`
	ActorID      string             `bson:"actor_id,omitempty" json:"actor_id,omitempty"`
	Action       string             `bson:"action" json:"action"`
	ResourceType string             `bson:"resource_type,omitempty" json:"resource_type,omitempty"`
	ResourceID   string             `bson:"resource_id,omitempty" json:"resource_id,omitempty"`
	Status       string             `bson:"status" json:"status"`
	RemoteAddr   string             `bson:"remote_addr,omitempty" json:"remote_addr,omitempty"`
	Message      string             `bson:"message,omitempty" json:"message,omitempty"`
	Metadata     map[string]string  `bson:"metadata,omitempty" json:"metadata,omitempty"`
}

const ScanSecretPurposeAuth = "scan_auth"

type ScanSecret struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	JobID      primitive.ObjectID `bson:"job_id" json:"job_id"`
	Purpose    string             `bson:"purpose" json:"purpose"`
	KeyID      string             `bson:"key_id,omitempty" json:"key_id,omitempty"`
	Nonce      string             `bson:"nonce" json:"-"`
	Ciphertext string             `bson:"ciphertext" json:"-"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	ExpiresAt  time.Time          `bson:"expires_at" json:"expires_at"`
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
	JobID          primitive.ObjectID `bson:"job_id,omitempty" json:"job_id,omitempty"`
	SchemaVersion  string             `bson:"schema_version" json:"schema_version"`
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

const (
	ScanJobStatusQueued    = "queued"
	ScanJobStatusRunning   = "running"
	ScanJobStatusCompleted = "completed"
	ScanJobStatusFailed    = "failed"
)

type ScanConfig struct {
	TargetURL     string            `bson:"target_url" json:"target_url"`
	Method        string            `bson:"method" json:"method"`
	Path          string            `bson:"path" json:"path"`
	Body          string            `bson:"body,omitempty" json:"body,omitempty"`
	Headers       map[string]string `bson:"headers,omitempty" json:"headers,omitempty"`
	TestType      string            `bson:"test_type" json:"test_type"`
	AuthSecretRef string            `bson:"auth_secret_ref,omitempty" json:"auth_secret_ref,omitempty"`
	ManualAuth    string            `bson:"-" json:"-"`
	AttackMethod  string            `bson:"attack_method,omitempty" json:"attack_method,omitempty"`
	PollutedBody  string            `bson:"polluted_body,omitempty" json:"polluted_body,omitempty"`
}

type ScanExecutionResult struct {
	SchemaVersion  string    `json:"schema_version"`
	TestType       string    `json:"test_type"`
	Vulnerable     bool      `json:"vulnerable"`
	Severity       string    `json:"severity"`
	Description    string    `json:"description"`
	ResponseStatus int       `json:"response_status"`
	ResponseBody   string    `json:"response_body"`
	ResponseHeader string    `json:"response_headers,omitempty"`
	Proof          string    `json:"proof"`
	Timestamp      time.Time `json:"timestamp"`
}

type ScanJob struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	InventoryID  primitive.ObjectID `bson:"inventory_id" json:"inventory_id"`
	Status       string             `bson:"status" json:"status"`
	TestType     string             `bson:"test_type" json:"test_type"`
	AttackMethod string             `bson:"attack_method,omitempty" json:"attack_method,omitempty"`
	Config       ScanConfig         `bson:"config" json:"config"`
	Error        string             `bson:"error,omitempty" json:"error,omitempty"`
	WorkerID     string             `bson:"worker_id,omitempty" json:"worker_id,omitempty"`
	Attempts     int                `bson:"attempts" json:"attempts"`
	ResultsCount int                `bson:"results_count" json:"results_count"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
	StartedAt    time.Time          `bson:"started_at,omitempty" json:"started_at,omitempty"`
	CompletedAt  time.Time          `bson:"completed_at,omitempty" json:"completed_at,omitempty"`
}
