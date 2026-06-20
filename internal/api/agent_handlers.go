package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/ingest"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	defaultAgentConfigPollSeconds = 30
	defaultAgentHeartbeatSeconds  = 30
	defaultAgentMaxPayloadSize    = 4096 * 4
	defaultAgentIgnoredPorts      = "9092,27017,6379"
	defaultCaptureReadSyscalls    = true
	defaultCaptureWriteSyscalls   = true
	defaultCaptureInboundTraffic  = true
	defaultCaptureOutboundTraffic = true
	defaultAgentAllowNonSocketFDs = false
	minAgentIntervalSeconds       = 5
	maxAgentIntervalSeconds       = 3600
)

type AgentHeartbeatRequest struct {
	AgentVersion string                 `json:"agent_version,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
	TargetMode   string                 `json:"target_mode,omitempty"`
	Stats        map[string]interface{} `json:"stats,omitempty"`
}

type AgentHeartbeatResponse struct {
	Status                    string    `json:"status"`
	AgentID                   string    `json:"agent_id"`
	ServerTime                time.Time `json:"server_time"`
	ConfigPollIntervalSeconds int       `json:"config_poll_interval_seconds"`
}

type AgentConfigResponse struct {
	SchemaVersion            string    `json:"schema_version"`
	ConfigVersion            string    `json:"config_version"`
	AgentID                  string    `json:"agent_id"`
	DataSourceID             string    `json:"data_source_id"`
	ServerTime               time.Time `json:"server_time"`
	PollIntervalSeconds      int       `json:"poll_interval_seconds"`
	HeartbeatIntervalSeconds int       `json:"heartbeat_interval_seconds"`
	TargetPorts              []int     `json:"target_ports,omitempty"`
	IgnorePorts              []int     `json:"ignore_ports,omitempty"`
	CaptureInbound           bool      `json:"capture_inbound"`
	CaptureOutbound          bool      `json:"capture_outbound"`
	CaptureReadSyscalls      bool      `json:"capture_read_syscalls"`
	CaptureWriteSyscalls     bool      `json:"capture_write_syscalls"`
	AllowNonSocketFDs        bool      `json:"allow_non_socket_fds"`
	MaxPayloadSize           int       `json:"max_payload_size"`
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.authorizeAgentControl(w, r)
	if !ok {
		return
	}
	if r.Body != nil {
		defer r.Body.Close()
		var req AgentHeartbeatRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
		if err := decoder.Decode(&req); err != nil && err.Error() != "EOF" {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	}
	writeJSON(w, http.StatusOK, AgentHeartbeatResponse{
		Status:                    "ok",
		AgentID:                   auth.AgentID,
		ServerTime:                time.Now().UTC(),
		ConfigPollIntervalSeconds: defaultAgentConfigPollSeconds,
	})
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.authorizeAgentControl(w, r)
	if !ok {
		return
	}
	accountID, err := primitive.ObjectIDFromHex(auth.TenantID)
	if err != nil {
		http.Error(w, "Invalid agent account", http.StatusUnauthorized)
		return
	}
	dataSourceID, err := primitive.ObjectIDFromHex(auth.DataSourceID)
	if err != nil {
		http.Error(w, "Invalid agent data source", http.StatusUnauthorized)
		return
	}
	source, err := s.DB.GetDataSourceForAccount(accountID, dataSourceID)
	if err != nil {
		http.Error(w, "Agent data source not found", http.StatusNotFound)
		return
	}
	if source.Type != core.DataSourceTypeEBPFLinux && source.Type != core.DataSourceTypeEBPFKubernetes {
		http.Error(w, "Agent data source is not eBPF", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, agentConfigResponse(auth, source))
}

func (s *Server) authorizeAgentControl(w http.ResponseWriter, r *http.Request) (*ingest.AgentAuth, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}
	if token == "" {
		http.Error(w, "Missing agent token", http.StatusUnauthorized)
		return nil, false
	}
	auth, ok := s.authenticateAgentToken(token)
	if !ok || auth == nil || auth.AgentID == "" {
		http.Error(w, "Invalid agent token", http.StatusUnauthorized)
		return nil, false
	}
	return auth, true
}

func agentConfigResponse(auth *ingest.AgentAuth, source core.DataSource) AgentConfigResponse {
	cfg := source.Config
	targetPorts := parseAgentConfigPorts(firstConfigValue(cfg, "target_ports", "target_port"))
	if len(targetPorts) == 0 {
		targetPorts = targetPortsFromURL(source.TargetURL)
	}
	ignorePorts := parseAgentConfigPorts(firstConfigValue(cfg, "ignore_ports", "ignored_ports"))
	if len(ignorePorts) == 0 {
		ignorePorts = parseAgentConfigPorts(defaultAgentIgnoredPorts)
	}
	now := time.Now().UTC()
	return AgentConfigResponse{
		SchemaVersion:            "agent.config.v1",
		ConfigVersion:            fmt.Sprintf("%s:%d", source.ID.Hex(), source.UpdatedAt.Unix()),
		AgentID:                  auth.AgentID,
		DataSourceID:             source.ID.Hex(),
		ServerTime:               now,
		PollIntervalSeconds:      boundedConfigInt(cfg, "config_poll_seconds", defaultAgentConfigPollSeconds, minAgentIntervalSeconds, maxAgentIntervalSeconds),
		HeartbeatIntervalSeconds: boundedConfigInt(cfg, "heartbeat_seconds", defaultAgentHeartbeatSeconds, minAgentIntervalSeconds, maxAgentIntervalSeconds),
		TargetPorts:              targetPorts,
		IgnorePorts:              ignorePorts,
		CaptureInbound:           configBool(cfg, "capture_inbound", defaultCaptureInboundTraffic),
		CaptureOutbound:          configBool(cfg, "capture_outbound", defaultCaptureOutboundTraffic),
		CaptureReadSyscalls:      configBool(cfg, "capture_read_syscalls", defaultCaptureReadSyscalls),
		CaptureWriteSyscalls:     configBool(cfg, "capture_write_syscalls", defaultCaptureWriteSyscalls),
		AllowNonSocketFDs:        configBool(cfg, "allow_non_socket_fds", defaultAgentAllowNonSocketFDs),
		MaxPayloadSize:           boundedConfigInt(cfg, "max_payload_size", defaultAgentMaxPayloadSize, 1, defaultAgentMaxPayloadSize),
	}
}

func firstConfigValue(cfg map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(cfg[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseAgentConfigPorts(raw string) []int {
	set := make(map[int]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		set[port] = struct{}{}
	}
	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func targetPortsFromURL(raw string) []int {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if parsed.Port() != "" {
		return parseAgentConfigPorts(parsed.Port())
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		return []int{80}
	case "https":
		return []int{443}
	default:
		return nil
	}
}

func boundedConfigInt(cfg map[string]string, key string, fallback int, min int, max int) int {
	value, err := strconv.Atoi(strings.TrimSpace(cfg[key]))
	if err != nil {
		value = fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func configBool(cfg map[string]string, key string, fallback bool) bool {
	raw := strings.TrimSpace(cfg[key])
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}
