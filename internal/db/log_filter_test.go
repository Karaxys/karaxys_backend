package db

import (
	"net/http"
	"testing"

	"karaxys_backend/internal/core"
)

func TestShouldDropTrafficLogDropsNoise(t *testing.T) {
	tests := []core.TrafficLog{
		{Method: http.MethodGet, Path: "/static/app.js"},
		{Method: http.MethodGet, Path: "/_next/static/chunk.css"},
		{Method: http.MethodGet, Path: "/favicon.ico"},
		{Method: http.MethodOptions, Path: "/api/users"},
		{Method: "", Path: "/api/users"},
		{Method: http.MethodGet, Path: ""},
	}

	for _, test := range tests {
		if !ShouldDropTrafficLog(test) {
			t.Fatalf("expected log to be dropped: %+v", test)
		}
	}
}

func TestShouldDropTrafficLogKeepsAPIRequests(t *testing.T) {
	tests := []core.TrafficLog{
		{Method: http.MethodGet, Path: "/api/users"},
		{Method: http.MethodPost, Path: "/api/users/123"},
		{Method: http.MethodPatch, URL: "http://api.example.local/v1/orders?id=1"},
	}

	for _, test := range tests {
		if ShouldDropTrafficLog(test) {
			t.Fatalf("expected log to be kept: %+v", test)
		}
	}
}
