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
}

type ScanResult struct {
	TestType    string    `json:"test_type"`
	Vulnerable  bool      `json:"vulnerable"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Proof       string    `json:"proof"`
	Timestamp   time.Time `json:"timestamp"`
}