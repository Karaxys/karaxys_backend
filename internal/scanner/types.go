package scanner
import(
	"time"
)

type ScanConfig struct{
	TargetURL     string
	Method        string
	Path          string
	Body          string
	Headers       map[string]string
	TestType      string
	ManualAuth    string
	AttackMethod  string
	PollutedBody  string
}

type ScanResult struct {
	TestType    string    `json:"test_type"`
	Vulnerable  bool      `json:"vulnerable"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	ResponseStatus int       `json:"response_status"`
	ResponseBody   string    `json:"response_body"`
	ResponseHeader string    `json:"response_headers,omitempty"`
	Proof       string    `json:"proof"`
	Timestamp   time.Time `json:"timestamp"`
}