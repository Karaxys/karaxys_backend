package api

import (
	"reflect"
	"testing"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/ingest"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestAgentConfigResponseUsesDataSourceConfig(t *testing.T) {
	sourceID := primitive.NewObjectID()
	source := core.DataSource{
		ID:        sourceID,
		Type:      core.DataSourceTypeEBPFLinux,
		TargetURL: "http://api.local:8080",
		Config: map[string]string{
			"target_ports":           "5000, 8080,5000",
			"ignore_ports":           "9092, bad, 27017",
			"capture_inbound":        "false",
			"capture_outbound":       "true",
			"capture_read_syscalls":  "true",
			"capture_write_syscalls": "false",
			"allow_non_socket_fds":   "true",
			"max_payload_size":       "999999",
			"config_poll_seconds":    "1",
			"heartbeat_seconds":      "999999",
		},
		UpdatedAt: time.Unix(123, 0).UTC(),
	}

	resp := agentConfigResponse(&ingest.AgentAuth{AgentID: "agent-1"}, source)
	if resp.SchemaVersion != "agent.config.v1" || resp.AgentID != "agent-1" || resp.DataSourceID != sourceID.Hex() {
		t.Fatalf("unexpected identity fields: %+v", resp)
	}
	if !reflect.DeepEqual(resp.TargetPorts, []int{5000, 8080}) {
		t.Fatalf("unexpected target ports: %+v", resp.TargetPorts)
	}
	if !reflect.DeepEqual(resp.IgnorePorts, []int{9092, 27017}) {
		t.Fatalf("unexpected ignore ports: %+v", resp.IgnorePorts)
	}
	if resp.CaptureInbound || !resp.CaptureOutbound || !resp.CaptureReadSyscalls || resp.CaptureWriteSyscalls || !resp.AllowNonSocketFDs {
		t.Fatalf("unexpected capture booleans: %+v", resp)
	}
	if resp.MaxPayloadSize != defaultAgentMaxPayloadSize {
		t.Fatalf("expected max payload to clamp to %d, got %d", defaultAgentMaxPayloadSize, resp.MaxPayloadSize)
	}
	if resp.PollIntervalSeconds != minAgentIntervalSeconds {
		t.Fatalf("expected poll interval clamp to %d, got %d", minAgentIntervalSeconds, resp.PollIntervalSeconds)
	}
	if resp.HeartbeatIntervalSeconds != maxAgentIntervalSeconds {
		t.Fatalf("expected heartbeat interval clamp to %d, got %d", maxAgentIntervalSeconds, resp.HeartbeatIntervalSeconds)
	}
}

func TestAgentConfigResponseFallsBackToTargetURLPortAndDefaultIgnoredPorts(t *testing.T) {
	source := core.DataSource{
		ID:        primitive.NewObjectID(),
		Type:      core.DataSourceTypeEBPFLinux,
		TargetURL: "https://api.local",
		UpdatedAt: time.Now().UTC(),
	}

	resp := agentConfigResponse(&ingest.AgentAuth{AgentID: "agent-1"}, source)
	if !reflect.DeepEqual(resp.TargetPorts, []int{443}) {
		t.Fatalf("unexpected target ports: %+v", resp.TargetPorts)
	}
	if !reflect.DeepEqual(resp.IgnorePorts, []int{6379, 9092, 27017}) {
		t.Fatalf("unexpected default ignored ports: %+v", resp.IgnorePorts)
	}
}
