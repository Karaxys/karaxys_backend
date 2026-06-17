package contracts

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	DirectionRead  uint8 = 0
	DirectionWrite uint8 = 1

	EventTypeData  uint8 = 0
	EventTypeClose uint8 = 1
)

var objectIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{24}$`)
var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func ValidateRawNetworkEvent(event RawNetworkEvent) error {
	var errs []error

	if event.SchemaVersion != SchemaRawNetworkV1 && event.SchemaVersion != SchemaRawV1Legacy {
		errs = append(errs, fmt.Errorf("schema_version must be %q", SchemaRawNetworkV1))
	}
	if event.CaptureSource != "ebpf" {
		errs = append(errs, errors.New("capture_source must be ebpf"))
	}
	if event.ChunkCount == 0 {
		errs = append(errs, errors.New("chunk_count must be greater than zero"))
	}
	if event.ChunkCount > 0 && event.ChunkIndex >= event.ChunkCount {
		errs = append(errs, errors.New("chunk_index must be lower than chunk_count"))
	}
	if event.Direction != DirectionRead && event.Direction != DirectionWrite {
		errs = append(errs, errors.New("direction must be 0 or 1"))
	}
	if event.EventType != EventTypeData && event.EventType != EventTypeClose {
		errs = append(errs, errors.New("event_type must be 0 or 1"))
	}
	if event.EventType == EventTypeData && event.Size == 0 {
		errs = append(errs, errors.New("data events must include a non-empty payload"))
	}
	if int(event.Size) != len(event.Payload) {
		errs = append(errs, fmt.Errorf("size must match decoded payload length: size=%d len=%d", event.Size, len(event.Payload)))
	}
	if event.OriginalSize > 0 && event.OriginalSize < event.Size {
		errs = append(errs, errors.New("original_size cannot be smaller than size"))
	}
	errs = append(errs, validateConnection(event.Connection)...)
	errs = append(errs, validateLoss(event.Loss)...)

	return errors.Join(errs...)
}

func ValidateHTTPConversation(conversation HTTPConversation) error {
	var errs []error

	if conversation.SchemaVersion != SchemaHTTPConversationV1 {
		errs = append(errs, fmt.Errorf("schema_version must be %q", SchemaHTTPConversationV1))
	}
	if !objectIDPattern.MatchString(conversation.ID.OID) {
		errs = append(errs, errors.New("_id.$oid must be a 24-character hex ObjectID"))
	}
	if conversation.CaptureSource == "" {
		errs = append(errs, errors.New("capture_source is required"))
	}
	if conversation.CapturedAt.Date.IsZero() {
		errs = append(errs, errors.New("captured_at.$date is required"))
	}

	req := conversation.HTTP.Request
	if req.Method == "" || strings.ToUpper(req.Method) != req.Method {
		errs = append(errs, errors.New("http.request.method must be uppercase"))
	}
	if req.URL == "" {
		errs = append(errs, errors.New("http.request.url is required"))
	} else if _, err := url.ParseRequestURI(req.URL); err != nil {
		errs = append(errs, fmt.Errorf("http.request.url is invalid: %w", err))
	}
	if req.Host == "" {
		errs = append(errs, errors.New("http.request.host is required"))
	}
	if req.Path == "" || !strings.HasPrefix(req.Path, "/") {
		errs = append(errs, errors.New("http.request.path must start with /"))
	}

	resp := conversation.HTTP.Response
	if resp.Status == "" {
		errs = append(errs, errors.New("http.response.status is required"))
	}
	if resp.StatusCode != nil && (*resp.StatusCode < 100 || *resp.StatusCode > 599) {
		errs = append(errs, errors.New("http.response.status_code must be between 100 and 599"))
	}

	errs = append(errs, validateConnection(conversation.Connection)...)
	errs = append(errs, validateLoss(conversation.Loss)...)

	return errors.Join(errs...)
}

func ValidateScanJob(job ScanJob) error {
	var errs []error

	if job.SchemaVersion != SchemaScanJobV1 {
		errs = append(errs, fmt.Errorf("schema_version must be %q", SchemaScanJobV1))
	}
	if strings.TrimSpace(job.JobID) == "" {
		errs = append(errs, errors.New("job_id is required"))
	}
	if job.CreatedAt.IsZero() {
		errs = append(errs, errors.New("created_at is required"))
	}
	if !objectIDPattern.MatchString(job.InventoryID) {
		errs = append(errs, errors.New("inventory_id must be a 24-character hex ObjectID"))
	}
	if strings.TrimSpace(job.TestType) == "" {
		errs = append(errs, errors.New("test_type is required"))
	}
	if job.Priority != "" && !isOneOf(job.Priority, "low", "normal", "high") {
		errs = append(errs, errors.New("priority must be low, normal, or high"))
	}

	target := job.Target
	if strings.TrimSpace(target.BaseURL) == "" {
		errs = append(errs, errors.New("target.base_url is required"))
	} else if _, err := url.ParseRequestURI(target.BaseURL); err != nil {
		errs = append(errs, fmt.Errorf("target.base_url is invalid: %w", err))
	}
	if target.Method == "" || strings.ToUpper(target.Method) != target.Method {
		errs = append(errs, errors.New("target.method must be uppercase"))
	}
	if target.Path == "" || !strings.HasPrefix(target.Path, "/") {
		errs = append(errs, errors.New("target.path must start with /"))
	}
	if target.AttackMethod != "" && strings.ToUpper(target.AttackMethod) != target.AttackMethod {
		errs = append(errs, errors.New("target.attack_method must be uppercase when set"))
	}

	if job.Auth != nil {
		switch job.Auth.Mode {
		case "none":
			if job.Auth.SecretRef != "" {
				errs = append(errs, errors.New("auth.secret_ref must be empty when auth.mode is none"))
			}
		case "secret_ref":
			if strings.TrimSpace(job.Auth.SecretRef) == "" {
				errs = append(errs, errors.New("auth.secret_ref is required when auth.mode is secret_ref"))
			}
		default:
			errs = append(errs, errors.New("auth.mode must be none or secret_ref"))
		}
	}

	if job.Limits != nil {
		if job.Limits.TimeoutSeconds < 0 || job.Limits.TimeoutSeconds > 3600 {
			errs = append(errs, errors.New("limits.timeout_seconds must be between 1 and 3600 when set"))
		}
		if job.Limits.MaxRequests < 0 {
			errs = append(errs, errors.New("limits.max_requests cannot be negative"))
		}
		if job.Limits.RateLimitPerSecond < 0 {
			errs = append(errs, errors.New("limits.rate_limit_per_second cannot be negative"))
		}
	}

	return errors.Join(errs...)
}

func ValidateScanResult(result ScanResult) error {
	var errs []error

	if result.SchemaVersion != SchemaScanResultV1 {
		errs = append(errs, fmt.Errorf("schema_version must be %q", SchemaScanResultV1))
	}
	if strings.TrimSpace(result.ResultID) == "" {
		errs = append(errs, errors.New("result_id is required"))
	}
	if strings.TrimSpace(result.JobID) == "" {
		errs = append(errs, errors.New("job_id is required"))
	}
	if !objectIDPattern.MatchString(result.InventoryID) {
		errs = append(errs, errors.New("inventory_id must be a 24-character hex ObjectID"))
	}
	if strings.TrimSpace(result.TestType) == "" {
		errs = append(errs, errors.New("test_type is required"))
	}
	if !isOneOf(result.Status, "passed", "failed", "error", "skipped") {
		errs = append(errs, errors.New("status must be passed, failed, error, or skipped"))
	}
	if !isOneOf(result.Severity, "info", "low", "medium", "high", "critical", "unknown") {
		errs = append(errs, errors.New("severity must be info, low, medium, high, critical, or unknown"))
	}
	if result.CreatedAt.IsZero() {
		errs = append(errs, errors.New("created_at is required"))
	}
	if result.Response != nil {
		if result.Response.StatusCode != nil && (*result.Response.StatusCode < 0 || *result.Response.StatusCode > 599) {
			errs = append(errs, errors.New("response.status_code must be between 0 and 599"))
		}
		if result.Response.BodySHA256 != "" && !sha256Pattern.MatchString(result.Response.BodySHA256) {
			errs = append(errs, errors.New("response.body_sha256 must be a SHA-256 hex digest"))
		}
	}

	return errors.Join(errs...)
}

func validateConnection(conn ConnectionMetadata) []error {
	var errs []error
	if conn.SrcPort < 0 || conn.SrcPort > 65535 {
		errs = append(errs, errors.New("connection.src_port must be between 0 and 65535"))
	}
	if conn.DstPort < 0 || conn.DstPort > 65535 {
		errs = append(errs, errors.New("connection.dst_port must be between 0 and 65535"))
	}
	if conn.Protocol != "" && !isOneOf(conn.Protocol, "tcp", "udp", "unix", "unknown") {
		errs = append(errs, errors.New("connection.protocol has invalid value"))
	}
	if conn.Family != "" && !isOneOf(conn.Family, "ipv4", "ipv6", "unix", "unknown") {
		errs = append(errs, errors.New("connection.family has invalid value"))
	}
	if conn.Role != "" && !isOneOf(conn.Role, "inbound", "outbound", "client", "server", "unknown") {
		errs = append(errs, errors.New("connection.role has invalid value"))
	}
	return errs
}

func validateLoss(loss LossMetadata) []error {
	var errs []error
	if loss.OriginalSize > 0 && loss.CapturedSize > loss.OriginalSize {
		errs = append(errs, errors.New("loss.captured_size cannot exceed loss.original_size"))
	}
	if loss.Truncated && loss.Reason == "" {
		errs = append(errs, errors.New("loss.reason is required when loss.truncated is true"))
	}
	return errs
}

func isOneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
