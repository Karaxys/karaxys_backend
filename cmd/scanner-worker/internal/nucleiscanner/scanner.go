package nucleiscanner

import (
	"context"
	"fmt"
	"karaxys_backend/internal/contracts"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/scanner"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type Scanner struct {
	registry *scanner.TemplateRegistry
}

func New(registry *scanner.TemplateRegistry) *Scanner {
	if registry == nil {
		registry = scanner.DefaultTemplateRegistry()
	}
	return &Scanner{registry: registry}
}

func (s *Scanner) ExecuteScanContext(ctx context.Context, config core.ScanConfig) ([]core.ScanExecutionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	log.Printf("Starting %s Scan on %s %s", config.TestType, config.Method, config.Path)
	yamlContent, err := s.registry.GetTemplate(config.TestType)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %v", err)
	}
	tmpPath, err := writeTemporaryTemplate(yamlContent)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpPath)

	if err := ensureNucleiIgnoreFile(); err != nil {
		log.Printf("Could not prepare nuclei ignore file: %v", err)
	}

	engineOptions := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.EnableMatcherStatus(),
	}
	if opts, ok := interactshOptions(); ok {
		engineOptions = append(engineOptions, nuclei.WithInteractshOptions(opts))
	}
	if config.RateLimitPerSecond > 0 {
		engineOptions = append(engineOptions, nuclei.WithGlobalRateLimitCtx(ctx, config.RateLimitPerSecond, time.Second))
	}
	if hasConcurrencyLimits(config) {
		engineOptions = append(engineOptions, nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           positiveOrDefault(config.TemplateConcurrency, 1),
			HostConcurrency:               positiveOrDefault(config.HostConcurrency, 1),
			HeadlessHostConcurrency:       positiveOrDefault(config.HostConcurrency, 1),
			HeadlessTemplateConcurrency:   positiveOrDefault(config.TemplateConcurrency, 1),
			JavascriptTemplateConcurrency: positiveOrDefault(config.TemplateConcurrency, 1),
			TemplatePayloadConcurrency:    positiveOrDefault(config.PayloadConcurrency, 1),
			ProbeConcurrency:              positiveOrDefault(config.ProbeConcurrency, 1),
		}))
	}
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx, engineOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to init nuclei engine: %v", err)
	}
	defer ne.Close()

	severityRule := severityRuleFor(s.registry, config.TestType)

	var results []core.ScanExecutionResult
	var mu sync.Mutex
	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		result, keep := buildResult(config, event, severityRule)
		if keep {
			results = append(results, result)
		}
	})

	vars := scanner.BuildTemplateVars(config)
	err = ne.ExecuteNucleiWithOpts([]string{scanner.ExecutionTarget(config.TargetURL)},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{tmpPath},
		}),
		nuclei.WithVars(vars.Vars),
	)
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %v", err)
	}

	return results, nil
}

// negativeMatcherNames are sentinel matcher names our hand-authored templates
// use to report a NON-finding (endpoint behaved securely / errored). Any other
// matched matcher — including unnamed matchers in community templates — counts
// as a finding.
var negativeMatcherNames = map[string]bool{
	"secure": true,
	"error":  true,
}

// buildResult converts a Nuclei result event into a scan result. The second
// return value reports whether the result should be kept: non-finding sentinel
// events (used only for observability under EnableMatcherStatus) are dropped.
func buildResult(config core.ScanConfig, event *output.ResultEvent, rule *severityRule) (core.ScanExecutionResult, bool) {
	matcherName := strings.ToLower(strings.TrimSpace(event.MatcherName))
	oob := event.Interaction != nil
	matched := event.MatcherStatus || oob
	if !matched || negativeMatcherNames[matcherName] {
		return core.ScanExecutionResult{}, false
	}

	severity := event.Info.SeverityHolder.Severity.String()
	similarity := bodySimilarity(config.OriginalResponseBody, event.Response)
	severity = rule.apply(severity, event.Response, similarity, oob)

	actualMethod := config.Method
	if config.AttackMethod != "" {
		actualMethod = config.AttackMethod
	}

	description := fmt.Sprintf("Scan Result: %s (Matcher: %s)", event.Matched, event.MatcherName)
	if oob {
		description = fmt.Sprintf("Out-of-band interaction confirmed: %s", event.Matched)
	}

	return core.ScanExecutionResult{
		SchemaVersion:   contracts.SchemaScanResultV1,
		TestType:        config.TestType,
		Vulnerable:      true,
		Severity:        severity,
		Description:     description,
		ResponseStatus:  statusCode(event),
		ResponseBody:    event.Response,
		Proof:           fmt.Sprintf("curl -v -X %s %s%s -H 'Authorization: %s'", actualMethod, config.TargetURL, config.Path, config.ManualAuth),
		SimilarityScore: similarity,
		OutOfBand:       oob,
		Timestamp:       time.Now().UTC(),
	}, true
}

func statusCode(event *output.ResultEvent) int {
	if event.Metadata != nil {
		if val, ok := event.Metadata["status_code"]; ok {
			switch v := val.(type) {
			case int:
				return v
			case float64:
				return int(v)
			}
		}
	}
	if len(event.Response) == 0 {
		return 0
	}
	limit := 100
	if len(event.Response) < limit {
		limit = len(event.Response)
	}
	re := regexp.MustCompile(`HTTP/\d\.\d\s+(\d{3})`)
	match := re.FindStringSubmatch(event.Response[:limit])
	if len(match) < 2 {
		return 0
	}
	code, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return code
}

func writeTemporaryTemplate(yamlContent string) (string, error) {
	cwd, _ := os.Getwd()
	tmpDir := filepath.Join(cwd, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create tmp directory: %v", err)
	}
	tmpFile, err := os.CreateTemp(tmpDir, "scan-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp template: %v", err)
	}
	path := tmpFile.Name()
	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	absPath, _ := filepath.Abs(path)
	return filepath.ToSlash(absPath), nil
}

func hasConcurrencyLimits(config core.ScanConfig) bool {
	return config.TemplateConcurrency > 0 ||
		config.HostConcurrency > 0 ||
		config.PayloadConcurrency > 0 ||
		config.ProbeConcurrency > 0
}

func positiveOrDefault(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func ensureNucleiIgnoreFile() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	nucleiDir := filepath.Join(configDir, "nuclei")
	if err := os.MkdirAll(nucleiDir, 0o700); err != nil {
		return err
	}
	ignoreFile := filepath.Join(nucleiDir, ".nuclei-ignore")
	file, err := os.OpenFile(ignoreFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}
