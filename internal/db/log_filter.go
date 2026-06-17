package db

import (
	"net/url"
	"path"
	"strings"

	"karaxys_backend/internal/core"
)

var noisyPathPrefixes = []string{
	"/assets/",
	"/static/",
	"/public/",
	"/_next/",
	"/favicon",
}

var noisyExtensions = map[string]struct{}{
	".css":   {},
	".gif":   {},
	".gz":    {},
	".ico":   {},
	".jpeg":  {},
	".jpg":   {},
	".js":    {},
	".map":   {},
	".mp3":   {},
	".mp4":   {},
	".pdf":   {},
	".png":   {},
	".svg":   {},
	".ttf":   {},
	".webm":  {},
	".woff":  {},
	".woff2": {},
	".zip":   {},
}

func ShouldDropTrafficLog(logEntry core.TrafficLog) bool {
	method := strings.ToUpper(strings.TrimSpace(logEntry.Method))
	if method == "" {
		return true
	}
	if method == "OPTIONS" {
		return true
	}

	requestPath := normalizedPath(logEntry.Path, logEntry.URL)
	if requestPath == "" {
		return true
	}

	lowerPath := strings.ToLower(requestPath)
	for _, prefix := range noisyPathPrefixes {
		if strings.HasPrefix(lowerPath, prefix) {
			return true
		}
	}
	if _, ok := noisyExtensions[path.Ext(lowerPath)]; ok {
		return true
	}

	return false
}

func normalizedPath(rawPath string, rawURL string) string {
	if rawPath != "" {
		if parsed, err := url.ParseRequestURI(rawPath); err == nil && parsed.Path != "" {
			return parsed.Path
		}
		return rawPath
	}
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Path
}
