package contracts

import "time"

const (
	SchemaRawNetworkV1       = "raw.network.v1"
	SchemaRawV1Legacy        = "raw.v1"
	SchemaHTTPConversationV1 = "http.conversation.v1"
	SchemaScanJobV1          = "scan.job.v1"
	SchemaScanResultV1       = "scan.result.v1"
)

type ObjectID struct {
	OID string `json:"$oid"`
}

type DateField struct {
	Date time.Time `json:"$date"`
}

type ConnectionMetadata struct {
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Family   string `json:"family,omitempty"`
	Role     string `json:"role,omitempty"`
}

type ProcessMetadata struct {
	PID  uint32 `json:"pid,omitempty"`
	Name string `json:"name,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

type ContainerMetadata struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Image     string `json:"image,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Node      string `json:"node,omitempty"`
}

type LossMetadata struct {
	Truncated       bool   `json:"truncated,omitempty"`
	OriginalSize    uint32 `json:"original_size,omitempty"`
	CapturedSize    uint32 `json:"captured_size,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SequenceGap     bool   `json:"sequence_gap,omitempty"`
	ExpectedNextSeq uint32 `json:"expected_next_seq,omitempty"`
	ActualSeq       uint32 `json:"actual_seq,omitempty"`
}

type RawNetworkEvent struct {
	SchemaVersion string             `json:"schema_version"`
	TenantID      string             `json:"tenant_id,omitempty"`
	ProjectID     string             `json:"project_id,omitempty"`
	AgentID       string             `json:"agent_id,omitempty"`
	CaptureSource string             `json:"capture_source"`
	CaptureMode   string             `json:"capture_mode,omitempty"`
	Timestamp     uint64             `json:"timestamp"`
	PID           uint32             `json:"pid"`
	TID           uint32             `json:"tid"`
	FD            uint32             `json:"fd"`
	Generation    uint32             `json:"generation"`
	Seq           uint32             `json:"seq"`
	ChunkIndex    uint16             `json:"chunk_index"`
	ChunkCount    uint16             `json:"chunk_count"`
	Direction     uint8              `json:"direction"`
	EventType     uint8              `json:"event_type"`
	Flags         uint8              `json:"flags"`
	OriginalSize  uint32             `json:"original_size,omitempty"`
	Size          uint32             `json:"size"`
	Payload       []byte             `json:"payload"`
	Connection    ConnectionMetadata `json:"connection,omitempty"`
	Process       ProcessMetadata    `json:"process,omitempty"`
	Container     ContainerMetadata  `json:"container,omitempty"`
	Loss          LossMetadata       `json:"loss,omitempty"`
}

type HTTPConversation struct {
	ID            ObjectID           `json:"_id"`
	SchemaVersion string             `json:"schema_version"`
	TenantID      string             `json:"tenant_id,omitempty"`
	ProjectID     string             `json:"project_id,omitempty"`
	AgentID       string             `json:"agent_id,omitempty"`
	CaptureSource string             `json:"capture_source"`
	CaptureMode   string             `json:"capture_mode,omitempty"`
	CapturedAt    DateField          `json:"captured_at"`
	Connection    ConnectionMetadata `json:"connection,omitempty"`
	Process       ProcessMetadata    `json:"process,omitempty"`
	Container     ContainerMetadata  `json:"container,omitempty"`
	Loss          LossMetadata       `json:"loss,omitempty"`
	HTTP          HTTPExchange       `json:"http"`
}

type HTTPExchange struct {
	Request  HTTPRequest  `json:"request"`
	Response HTTPResponse `json:"response"`
}

type HTTPRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
}

type HTTPResponse struct {
	Status     string              `json:"status"`
	StatusCode *int                `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
}

type ScanJob struct {
	SchemaVersion string      `json:"schema_version"`
	TenantID      string      `json:"tenant_id,omitempty"`
	ProjectID     string      `json:"project_id,omitempty"`
	JobID         string      `json:"job_id"`
	CreatedBy     string      `json:"created_by,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
	InventoryID   string      `json:"inventory_id"`
	TestType      string      `json:"test_type"`
	TemplateID    string      `json:"template_id,omitempty"`
	Priority      string      `json:"priority,omitempty"`
	Target        ScanTarget  `json:"target"`
	Auth          *ScanAuth   `json:"auth,omitempty"`
	Limits        *ScanLimits `json:"limits,omitempty"`
}

type ScanTarget struct {
	BaseURL      string            `json:"base_url"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	PollutedBody string            `json:"polluted_body,omitempty"`
	AttackMethod string            `json:"attack_method,omitempty"`
}

type ScanAuth struct {
	Mode      string `json:"mode"`
	SecretRef string `json:"secret_ref,omitempty"`
}

type ScanLimits struct {
	TimeoutSeconds     int `json:"timeout_seconds,omitempty"`
	MaxRequests        int `json:"max_requests,omitempty"`
	RateLimitPerSecond int `json:"rate_limit_per_second,omitempty"`
}

type ScanResult struct {
	SchemaVersion string        `json:"schema_version"`
	TenantID      string        `json:"tenant_id,omitempty"`
	ProjectID     string        `json:"project_id,omitempty"`
	ResultID      string        `json:"result_id"`
	JobID         string        `json:"job_id"`
	InventoryID   string        `json:"inventory_id"`
	TestType      string        `json:"test_type"`
	TemplateID    string        `json:"template_id,omitempty"`
	Status        string        `json:"status"`
	Vulnerable    bool          `json:"vulnerable"`
	Severity      string        `json:"severity"`
	Description   string        `json:"description,omitempty"`
	Proof         string        `json:"proof,omitempty"`
	Response      *ScanResponse `json:"response,omitempty"`
	Error         string        `json:"error,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

type ScanResponse struct {
	StatusCode  *int                `json:"status_code,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	BodyExcerpt string              `json:"body_excerpt,omitempty"`
	BodySHA256  string              `json:"body_sha256,omitempty"`
}
