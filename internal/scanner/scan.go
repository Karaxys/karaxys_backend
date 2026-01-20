package scanner
import(
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type Scanner struct {
	// builder config goes here
}

func NewScanner() *Scanner{
	return &Scanner{}
}

func (s *Scanner) ExecuteScan(config ScanConfig) ([]ScanResult, error) {
	log.Printf("Starting %s Scan on %s %s", config.TestType, config.Method, config.Path)
	yamlContent, err := GetTemplate(config.TestType)
	if err != nil{
		return nil, fmt.Errorf("failed to get template: %v", err)
	}

	if err := os.MkdirAll("tmp", 0755); err != nil{
		return nil, fmt.Errorf("failed to create tmp directory: %v", err)
	}
	tmpFile, err := os.CreateTemp("tmp", "scan-*.yaml")
	if err != nil{
		return nil, fmt.Errorf("failed to create temp template: %v", err)
	}
	absPath, _ := filepath.Abs(tmpFile.Name())
	defer os.Remove(absPath)

	if _, err := tmpFile.WriteString(yamlContent); err != nil{
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

	// This is the function Nuclei will call when it finds a bug
	onResult := func(event *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		// DEBUG: Dump the full event
		eventBytes, _ := json.MarshalIndent(event, "", "  ")
		log.Printf("🔎 Nuclei Raw Event:\n%s", string(eventBytes))
		isVuln := event.MatcherName == "vulnerable"
		severity := event.Info.SeverityHolder.Severity.String()

		res := ScanResult{
			TestType:    config.TestType,
			Vulnerable:  isVuln,
			Severity:    severity,
			Description: fmt.Sprintf("BOLA Scan Result: %s (Matcher: %s)", event.Matched, event.MatcherName),
			Proof:       fmt.Sprintf("curl -X %s %s%s -H 'Authorization: %s'", config.Method, config.TargetURL, config.Path, config.ManualAuth),
			Timestamp:   time.Now(),
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

	vars = append(vars, fmt.Sprintf("Hostname=%s", hostname))
	vars = append(vars, fmt.Sprintf("method=%s", config.Method))
	vars = append(vars, fmt.Sprintf("path=%s", config.Path))
	vars = append(vars, fmt.Sprintf("body=%s", config.Body))
	vars = append(vars, fmt.Sprintf("body_len=%d", len(config.Body)))
	vars = append(vars, fmt.Sprintf("attack_token=%s", config.ManualAuth))

	execTarget := config.TargetURL
	execTarget = strings.Replace(execTarget, "localhost", "127.0.0.1", 1)
	err = ne.ExecuteNucleiWithOpts([]string{execTarget},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{absPath},
		}),
		nuclei.WithVars(vars),
	)
	if err != nil{
		return nil, fmt.Errorf("nuclei execution failed: %v", err)
	}

	return results, nil
}