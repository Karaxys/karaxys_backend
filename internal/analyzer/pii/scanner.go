package pii

import (
	"strings"
)

func Scan(key string, value string) []string {
	var detected []string
	key = strings.ToLower(key)

	for _, rule := range Rules {
		if len(rule.Keywords) > 0 {
			matchFound := false
			for _, kw := range rule.Keywords {
				if strings.Contains(key, kw) {
					matchFound = true
					break
				}
			}
			if !matchFound {
				continue
			}
		}
		if !rule.Regex.MatchString(value) {
			continue
		}
		if rule.Verifier != nil {
			if !rule.Verifier(value) {
				continue
			}
		}
		detected = append(detected, rule.Name)
	}
	return detected
}