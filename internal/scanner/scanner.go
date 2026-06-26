package scanner

import (
	"context"
	"fmt"
	"karaxys_backend/internal/core"
	"net/url"
	"sort"
	"strings"
)

type Executor interface {
	ExecuteScanContext(ctx context.Context, config core.ScanConfig) ([]core.ScanExecutionResult, error)
}

type TemplateVars struct {
	Vars        []string
	Hostname    string
	BodyPayload string
	HeaderBlock string
}

func BuildTemplateVars(config core.ScanConfig) TemplateVars {
	hostname := hostnameFor(config.TargetURL)
	bodyPayload := config.Body
	if config.PollutedBody != "" {
		bodyPayload = config.PollutedBody
	}
	headerBlock := BuildHeaderBlock(config.Headers)

	vars := []string{
		fmt.Sprintf("Hostname=%s", hostname),
		fmt.Sprintf("method=%s", config.Method),
		fmt.Sprintf("path=%s", config.Path),
		fmt.Sprintf("attack_token=%s", config.ManualAuth),
		fmt.Sprintf("attack_method=%s", config.AttackMethod),
		fmt.Sprintf("body=%s", bodyPayload),
		fmt.Sprintf("polluted_body=%s", bodyPayload),
		fmt.Sprintf("body_len=%d", len(bodyPayload)),
		fmt.Sprintf("header_block=%s", headerBlock),
	}
	return TemplateVars{
		Vars:        vars,
		Hostname:    hostname,
		BodyPayload: bodyPayload,
		HeaderBlock: headerBlock,
	}
}

func BuildHeaderBlock(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		if headerExcludedFromTemplateVars(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})
	var block strings.Builder
	for _, key := range keys {
		block.WriteString(fmt.Sprintf("%s: %s\n", key, headers[key]))
	}
	return block.String()
}

func ExecutionTarget(targetURL string) string {
	return strings.Replace(strings.TrimSpace(targetURL), "localhost", "127.0.0.1", 1)
}

func headerExcludedFromTemplateVars(key string) bool {
	return strings.EqualFold(key, "Authorization") ||
		strings.EqualFold(key, "Host") ||
		strings.EqualFold(key, "Content-Length") ||
		strings.EqualFold(key, "Connection")
}

func hostnameFor(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		return targetURL
	}
	return parsed.Host
}
