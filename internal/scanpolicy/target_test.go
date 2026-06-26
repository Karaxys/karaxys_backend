package scanpolicy

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidateTargetURLRejectsPrivateNetworkWhenDisabled(t *testing.T) {
	policy := TargetPolicy{
		AllowPrivateTargets: false,
		Resolver: fixedResolver(map[string][]net.IP{
			"internal.example.com": {net.ParseIP("10.0.0.10")},
		}),
	}

	err := policy.ValidateTargetURL(context.Background(), "http://internal.example.com/api")
	if !errors.Is(err, ErrTargetPrivateNetwork) {
		t.Fatalf("expected ErrTargetPrivateNetwork, got %v", err)
	}
}

func TestValidateTargetURLAllowsPrivateNetworkWhenExplicitlyEnabled(t *testing.T) {
	policy := TargetPolicy{
		AllowPrivateTargets: true,
		Resolver: fixedResolver(map[string][]net.IP{
			"localhost": {net.ParseIP("127.0.0.1")},
		}),
	}

	if err := policy.ValidateTargetURL(context.Background(), "http://localhost:3000"); err != nil {
		t.Fatalf("expected localhost to be allowed in explicit local mode, got %v", err)
	}
}

func TestValidateTargetURLAlwaysRejectsMetadataEndpoint(t *testing.T) {
	policy := TargetPolicy{AllowPrivateTargets: true}

	err := policy.ValidateTargetURL(context.Background(), "http://169.254.169.254/latest/meta-data")
	if !errors.Is(err, ErrTargetMetadata) {
		t.Fatalf("expected ErrTargetMetadata, got %v", err)
	}
}

func TestValidateTargetURLRequiresAllowlistWhenConfigured(t *testing.T) {
	policy := TargetPolicy{
		AllowPrivateTargets: true,
		Allowlist:           []string{"*.example.com"},
		Resolver: fixedResolver(map[string][]net.IP{
			"api.example.com": {net.ParseIP("203.0.113.10")},
			"evil.test":       {net.ParseIP("203.0.113.20")},
		}),
	}

	if err := policy.ValidateTargetURL(context.Background(), "http://api.example.com"); err != nil {
		t.Fatalf("expected allowlisted host to pass, got %v", err)
	}
	err := policy.ValidateTargetURL(context.Background(), "http://evil.test")
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("expected ErrTargetNotAllowed, got %v", err)
	}
}

func TestValidateTargetURLDenylistWins(t *testing.T) {
	policy := TargetPolicy{
		AllowPrivateTargets: true,
		Allowlist:           []string{"*.example.com"},
		Denylist:            []string{"blocked.example.com"},
		Resolver: fixedResolver(map[string][]net.IP{
			"blocked.example.com": {net.ParseIP("203.0.113.10")},
		}),
	}

	err := policy.ValidateTargetURL(context.Background(), "http://blocked.example.com")
	if !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("expected ErrTargetDenied, got %v", err)
	}
}

func TestValidateTargetURLRejectsUnsupportedScheme(t *testing.T) {
	policy := TargetPolicy{AllowPrivateTargets: true}

	err := policy.ValidateTargetURL(context.Background(), "file:///etc/passwd")
	if !errors.Is(err, ErrTargetURLInvalid) {
		t.Fatalf("expected ErrTargetURLInvalid, got %v", err)
	}
}

func fixedResolver(values map[string][]net.IP) Resolver {
	return func(_ context.Context, host string) ([]net.IP, error) {
		if ips, ok := values[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Name: host, Err: "not found"}
	}
}
