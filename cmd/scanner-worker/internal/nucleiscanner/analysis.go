package nucleiscanner

import (
	"os"
	"strings"

	"karaxys_backend/internal/scanner"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

// interactshOptions decides whether out-of-band (blind SSRF / blind injection)
// detection is enabled and against which server. Opt-in by design: a scanner
// that may run against customer infrastructure should not silently exfiltrate
// callback data to a public OAST server. Precedence:
//   - KARAXYS_SCAN_INTERACTSH_SERVER set → use it (self-hosted, preferred)
//   - else KARAXYS_SCAN_OOB_ENABLED truthy → nuclei's default public servers
//   - else disabled
func interactshOptions() (nuclei.InteractshOpts, bool) {
	server := strings.TrimSpace(os.Getenv("KARAXYS_SCAN_INTERACTSH_SERVER"))
	if server != "" {
		return nuclei.InteractshOpts{
			ServerURL:     server,
			Authorization: strings.TrimSpace(os.Getenv("KARAXYS_SCAN_INTERACTSH_TOKEN")),
		}, true
	}
	if envTruthy(os.Getenv("KARAXYS_SCAN_OOB_ENABLED")) {
		// Empty ServerURL → nuclei falls back to its built-in public OAST servers.
		return nuclei.InteractshOpts{}, true
	}
	return nuclei.InteractshOpts{}, false
}

func envTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// severityRule is the worker-side view of a template's dynamic-severity policy,
// combining the data-driven rule from template metadata with runtime signals
// (out-of-band confirmation, response similarity).
type severityRule struct {
	sensitiveMarkers []string
	downgradeTo      string
}

func severityRuleFor(registry *scanner.TemplateRegistry, testType string) *severityRule {
	if registry == nil {
		return nil
	}
	meta, err := registry.GetMetadata(testType)
	if err != nil || meta.DynamicSeverity == nil {
		return nil
	}
	return &severityRule{
		sensitiveMarkers: meta.DynamicSeverity.SensitiveMarkers,
		downgradeTo:      strings.TrimSpace(meta.DynamicSeverity.DowngradeTo),
	}
}

// apply adjusts the base severity. Out-of-band confirmation is authoritative and
// never downgraded. Otherwise, if the rule declares sensitive markers and none
// appear in the response, the finding is downgraded.
func (r *severityRule) apply(base string, responseBody string, similarity float64, oob bool) string {
	if oob {
		return base
	}
	if r == nil || r.downgradeTo == "" || len(r.sensitiveMarkers) == 0 {
		return base
	}
	lower := strings.ToLower(responseBody)
	for _, marker := range r.sensitiveMarkers {
		marker = strings.ToLower(strings.TrimSpace(marker))
		if marker != "" && strings.Contains(lower, marker) {
			return base
		}
	}
	return r.downgradeTo
}

// bodySimilarity returns a 0..1 trigram-Jaccard similarity between the baseline
// captured response and the test response (1 = identical). Cheap and
// dependency-free — used to flag likely false positives where a "vulnerable"
// response barely differs from the endpoint's normal output. Returns 0 when
// there is no baseline to compare against.
func bodySimilarity(baseline, candidate string) float64 {
	baseline = normalizeForSimilarity(baseline)
	candidate = normalizeForSimilarity(candidate)
	if baseline == "" || candidate == "" {
		return 0
	}
	if baseline == candidate {
		return 1
	}
	a := trigrams(baseline)
	b := trigrams(candidate)
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	intersection := 0
	for gram := range a {
		if b[gram] {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

const similarityInputCap = 64 * 1024

func normalizeForSimilarity(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > similarityInputCap {
		s = s[:similarityInputCap]
	}
	return strings.ToLower(s)
}

func trigrams(s string) map[string]bool {
	set := make(map[string]bool)
	runes := []rune(s)
	if len(runes) < 3 {
		set[s] = true
		return set
	}
	for i := 0; i+3 <= len(runes); i++ {
		set[string(runes[i:i+3])] = true
	}
	return set
}
