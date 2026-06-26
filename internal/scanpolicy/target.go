package scanpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	ErrTargetURLInvalid     = errors.New("target url is invalid")
	ErrTargetDenied         = errors.New("target is denied by scan policy")
	ErrTargetNotAllowed     = errors.New("target is not in scan allowlist")
	ErrTargetPrivateNetwork = errors.New("target resolves to a private or reserved network")
	ErrTargetMetadata       = errors.New("target resolves to a cloud metadata endpoint")
)

type Resolver func(ctx context.Context, host string) ([]net.IP, error)

type TargetPolicy struct {
	AllowPrivateTargets bool
	Allowlist           []string
	Denylist            []string
	Resolver            Resolver
	LookupTimeout       time.Duration
}

func LoadTargetPolicyFromEnv() TargetPolicy {
	return TargetPolicy{
		AllowPrivateTargets: boolEnvDefault("KARAXYS_SCAN_ALLOW_PRIVATE_TARGETS", !isProduction()),
		Allowlist:           splitCSVEnv("KARAXYS_SCAN_TARGET_ALLOWLIST"),
		Denylist:            splitCSVEnv("KARAXYS_SCAN_TARGET_DENYLIST"),
		LookupTimeout:       3 * time.Second,
	}
}

func (p TargetPolicy) ValidateTargetURL(ctx context.Context, raw string) error {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Host == "" {
		return fmt.Errorf("%w: must be an absolute http(s) URL", ErrTargetURLInvalid)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: userinfo is not allowed", ErrTargetURLInvalid)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%w: scheme must be http or https", ErrTargetURLInvalid)
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("%w: host is required", ErrTargetURLInvalid)
	}
	if parsed.Port() != "" {
		if _, err := net.LookupPort("tcp", parsed.Port()); err != nil {
			return fmt.Errorf("%w: invalid port", ErrTargetURLInvalid)
		}
	}

	ips, err := p.resolve(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: could not resolve host %q: %v", ErrTargetURLInvalid, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: host resolved to no addresses", ErrTargetURLInvalid)
	}

	if p.matchesAny(host, ips, p.Denylist) {
		return fmt.Errorf("%w: %s", ErrTargetDenied, host)
	}
	if len(p.Allowlist) > 0 && !p.matchesAny(host, ips, p.Allowlist) {
		return fmt.Errorf("%w: %s", ErrTargetNotAllowed, host)
	}
	for _, ip := range ips {
		if isMetadataEndpoint(host, ip) {
			return fmt.Errorf("%w: %s", ErrTargetMetadata, ip.String())
		}
		if !p.AllowPrivateTargets && isPrivateOrReserved(ip) {
			return fmt.Errorf("%w: %s", ErrTargetPrivateNetwork, ip.String())
		}
	}
	return nil
}

func (p TargetPolicy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := p.LookupTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	return resolver(ctx, host)
}

func (p TargetPolicy) matchesAny(host string, ips []net.IP, patterns []string) bool {
	for _, pattern := range patterns {
		if matchTargetPattern(host, ips, pattern) {
			return true
		}
	}
	return false
}

func matchTargetPattern(host string, ips []net.IP, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if pattern == "" {
		return false
	}
	if _, network, err := net.ParseCIDR(pattern); err == nil {
		for _, ip := range ips {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}
	if ip := net.ParseIP(pattern); ip != nil {
		for _, candidate := range ips {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}
	pattern = strings.TrimSuffix(pattern, ".")
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}

func isPrivateOrReserved(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range reservedNetworks {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isMetadataEndpoint(host string, ip net.IP) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch host {
	case "metadata", "metadata.google.internal":
		return true
	}
	for _, cidr := range metadataNetworks {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func splitCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func boolEnvDefault(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func isProduction() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("KARAXYS_ENV")), "production")
}

var reservedNetworks = mustCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"2001:db8::/32",
)

var metadataNetworks = mustCIDRs(
	"169.254.169.254/32",
	"100.100.100.200/32",
	"fd00:ec2::254/128",
)

func mustCIDRs(values ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		out = append(out, network)
	}
	return out
}
