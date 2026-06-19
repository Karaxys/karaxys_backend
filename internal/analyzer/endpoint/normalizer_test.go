package endpoint

import "testing"

func TestNormalizePathDeterministicDynamicSegments(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		params  []string
	}{
		{
			name:    "numeric ids preserve version",
			path:    "/api/v1/users/123/orders/456",
			pattern: "/api/v1/users/{user_id}/orders/{order_id}",
			params:  []string{"user_id", "order_id"},
		},
		{
			name:    "uuid",
			path:    "/v2/sessions/550e8400-e29b-41d4-a716-446655440000",
			pattern: "/v2/sessions/{session_uuid}",
			params:  []string{"session_uuid"},
		},
		{
			name:    "object id",
			path:    "/users/507f1f77bcf86cd799439011",
			pattern: "/users/{user_object_id}",
			params:  []string{"user_object_id"},
		},
		{
			name:    "hash",
			path:    "/files/e3b0c44298fc1c149afbf4c8996fb924",
			pattern: "/files/{file_hash}",
			params:  []string{"file_hash"},
		},
		{
			name:    "slug preserved",
			path:    "/posts/my-first-api-security-post",
			pattern: "/posts/my-first-api-security-post",
			params:  nil,
		},
		{
			name:    "mixed prefixed id",
			path:    "/invoices/inv_123456",
			pattern: "/invoices/{invoice_id}",
			params:  []string{"invoice_id"},
		},
		{
			name:    "repeated resource param names are unique",
			path:    "/users/123/users/456",
			pattern: "/users/{user_id}/users/{user_id_2}",
			params:  []string{"user_id", "user_id_2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			normalized := NormalizePath(test.path, "")
			if normalized.Pattern != test.pattern {
				t.Fatalf("pattern mismatch: got=%s want=%s", normalized.Pattern, test.pattern)
			}
			if len(normalized.Parameters) != len(test.params) {
				t.Fatalf("param count mismatch: got=%d want=%d", len(normalized.Parameters), len(test.params))
			}
			for i, want := range test.params {
				if normalized.Parameters[i].Name != want {
					t.Fatalf("param[%d] mismatch: got=%s want=%s", i, normalized.Parameters[i].Name, want)
				}
			}
		})
	}
}

func TestNormalizePathFallsBackToURLPath(t *testing.T) {
	normalized := NormalizePath("", "https://api.example.com/v1/users/123?expand=true")
	if normalized.Pattern != "/v1/users/{user_id}" {
		t.Fatalf("unexpected pattern: %s", normalized.Pattern)
	}
}

func TestQueryParameters(t *testing.T) {
	params := QueryParameters("https://api.example.com/v1/users?limit=10&email=a@example.com")
	if len(params) != 2 {
		t.Fatalf("unexpected param count: %d", len(params))
	}
	seen := map[string]string{}
	for _, param := range params {
		seen[param.Name] = param.DataType
	}
	if seen["limit"] != "integer" {
		t.Fatalf("limit type mismatch: %s", seen["limit"])
	}
	if seen["email"] != "string" {
		t.Fatalf("email type mismatch: %s", seen["email"])
	}
}

func TestCookieParameters(t *testing.T) {
	params := CookieParameters(map[string][]string{
		"Cookie": {"session_id=abc123; theme=dark"},
	})
	if len(params) != 2 {
		t.Fatalf("unexpected cookie param count: %d", len(params))
	}
	if params[0].Name != "session_id" || params[0].Location != LocationCookie {
		t.Fatalf("unexpected first cookie param: %#v", params[0])
	}
}

func TestFingerprintStableAndTenantAware(t *testing.T) {
	first := Fingerprint("tenant-a", "project", "get", "https://api.example.com", "/v1/users/{user_id}")
	second := Fingerprint("tenant-a", "project", "GET", "https://api.example.com/", "/v1/users/{user_id}")
	third := Fingerprint("tenant-b", "project", "GET", "https://api.example.com", "/v1/users/{user_id}")
	if first != second {
		t.Fatalf("expected normalized equivalent fingerprints to match")
	}
	if first == third {
		t.Fatalf("expected tenant-aware fingerprints to differ")
	}
}
