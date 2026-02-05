package scanner
import(
	"context"
	"fmt"
	"log"
	"net/url"
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

type Scanner struct{}

func NewScanner() *Scanner{
	return &Scanner{}
}

func (s *Scanner) ExecuteScan(config ScanConfig) ([]ScanResult, error) {
	log.Printf("Starting %s Scan on %s %s", config.TestType, config.Method, config.Path)
	yamlContent, err := GetTemplate(config.TestType)
	if err != nil{
		return nil, fmt.Errorf("failed to get template: %v", err)
	}
	cwd, _ := os.Getwd()
	tmpDir := filepath.Join(cwd, "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil{
		return nil, fmt.Errorf("failed to create tmp directory: %v", err)
	}
	tmpFile, err := os.CreateTemp(tmpDir, "scan-*.yaml")
	if err != nil{
		return nil, fmt.Errorf("failed to create temp template: %v", err)
	}
	absPath, _ := filepath.Abs(tmpFile.Name())
	normalizedPath := filepath.ToSlash(absPath)
	defer os.Remove(absPath)

	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(
		context.Background(),
		nuclei.DisableUpdateCheck(),
		nuclei.EnableMatcherStatus(),
	)
	if err != nil{
		return nil, fmt.Errorf("failed to init nuclei engine: %v", err)
	}
	defer ne.Close()
	var results []ScanResult
	var mu sync.Mutex

	onResult := func(event *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		matcherName := strings.ToLower(event.MatcherName)
		isVuln := matcherName == "vulnerable" ||
			matcherName == "critical-data-leak" ||
			matcherName == "high-sensitive-exposure" ||
			matcherName == "low-method-allowed"
		severity := event.Info.SeverityHolder.Severity.String()
		actualMethod := config.Method
		if config.AttackMethod != "" {
			actualMethod = config.AttackMethod
		}

		var statusCode int
		if event.Metadata != nil {
			if val, ok := event.Metadata["status_code"]; ok {
				switch v := val.(type){
				case int:
					statusCode = v
				case float64:
					statusCode = int(v)
				}
			}
		}
		if statusCode == 0 && len(event.Response) > 0 {
			limit := 100
			if len(event.Response) < limit {
				limit = len(event.Response)
			}
			head := event.Response[:limit]
			re := regexp.MustCompile(`HTTP/\d\.\d\s+(\d{3})`)
			match := re.FindStringSubmatch(head)
			if len(match) >= 2 {
				if code, err := strconv.Atoi(match[1]); err == nil {
					statusCode = code
				}
			}
		}

		res := ScanResult{
			TestType:       config.TestType,
			Vulnerable:     isVuln,
			Severity:       severity,
			Description:    fmt.Sprintf("Scan Result: %s (Matcher: %s)", event.Matched, event.MatcherName),
			ResponseStatus: statusCode,
			ResponseBody:   event.Response,
			Proof:          fmt.Sprintf("curl -v -X %s %s%s -H 'Authorization: %s'", actualMethod, config.TargetURL, config.Path, config.ManualAuth),
			Timestamp:      time.Now(),
		}
		results = append(results, res)
	}

	ne.GlobalResultCallback(onResult)
	var vars []string
	u, _ := url.Parse(config.TargetURL)
	hostname := u.Host
	if hostname == "" {
		hostname = config.TargetURL
	}
	bodyPayload := config.Body
	if config.PollutedBody != "" {
		bodyPayload = config.PollutedBody
	}

	vars = append(vars, fmt.Sprintf("Hostname=%s", hostname))
	vars = append(vars, fmt.Sprintf("method=%s", config.Method))
	vars = append(vars, fmt.Sprintf("path=%s", config.Path))
	vars = append(vars, fmt.Sprintf("attack_token=%s", config.ManualAuth))
	vars = append(vars, fmt.Sprintf("attack_method=%s", config.AttackMethod))
	vars = append(vars, fmt.Sprintf("body=%s", bodyPayload))
	vars = append(vars, fmt.Sprintf("polluted_body=%s", bodyPayload))
	vars = append(vars, fmt.Sprintf("body_len=%d", len(bodyPayload)))

	var headerBlock strings.Builder
	for k, v := range config.Headers{
		if strings.EqualFold(k, "Authorization") ||
			strings.EqualFold(k, "Host") ||
			strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Connection") {
			continue
		}
		headerBlock.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	vars = append(vars, fmt.Sprintf("header_block=%s", headerBlock.String()))

	execTarget := config.TargetURL
	execTarget = strings.Replace(execTarget, "localhost", "127.0.0.1", 1)
	err = ne.ExecuteNucleiWithOpts([]string{execTarget},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{normalizedPath},
		}),
		nuclei.WithVars(vars),
	)
	if err != nil{
		return nil, fmt.Errorf("nuclei execution failed: %v", err)
	}

	return results, nil
}