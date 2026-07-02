package nucleiscanner

import "testing"

func TestBodySimilarity(t *testing.T) {
	if s := bodySimilarity("", "anything"); s != 0 {
		t.Fatalf("empty baseline should score 0, got %f", s)
	}
	if s := bodySimilarity("hello world", "hello world"); s != 1 {
		t.Fatalf("identical should score 1, got %f", s)
	}
	high := bodySimilarity("the quick brown fox", "the quick brown fux")
	low := bodySimilarity("the quick brown fox", "completely different content here")
	if !(high > low) {
		t.Fatalf("expected near-identical (%f) to score higher than dissimilar (%f)", high, low)
	}
	if high < 0.5 {
		t.Fatalf("near-identical strings should score high, got %f", high)
	}
}

func TestSeverityRuleApply(t *testing.T) {
	rule := &severityRule{sensitiveMarkers: []string{"password", "token"}, downgradeTo: "medium"}

	if got := rule.apply("high", `{"user":"bob"}`, 0.1, false); got != "medium" {
		t.Fatalf("expected downgrade when no marker present, got %s", got)
	}
	if got := rule.apply("high", `{"password":"secret"}`, 0.1, false); got != "high" {
		t.Fatalf("expected no downgrade when marker present, got %s", got)
	}
	if got := rule.apply("high", `{"user":"bob"}`, 0.1, true); got != "high" {
		t.Fatalf("OOB findings must never be downgraded, got %s", got)
	}

	var nilRule *severityRule
	if got := nilRule.apply("critical", "anything", 0, false); got != "critical" {
		t.Fatalf("nil rule should leave severity unchanged, got %s", got)
	}
}
