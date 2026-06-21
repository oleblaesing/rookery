package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// STSPolicy is a recipient domain's MTA-STS policy (RFC 8461). A nil *STSPolicy
// means the domain publishes no policy and delivery stays opportunistic.
type STSPolicy struct {
	Mode string   // "enforce", "testing", or "none"
	MX   []string // allowed MX host patterns, may contain a leading "*." label
	ID   string   // policy id from the _mta-sts TXT record
}

// PolicyCache stores resolved policies between deliveries. The redis-backed
// implementation lives in internal/cache; smtp stays free of that dependency.
// A nil cache is valid: ResolvePolicy then fetches live every time.
type PolicyCache interface {
	Get(ctx context.Context, domain string) (*STSPolicy, bool, error)
	Put(ctx context.Context, domain string, p *STSPolicy, ttl time.Duration) error
}

const (
	stsMaxAgeCap   = 24 * time.Hour
	stsMaxAgeFloor = 5 * time.Minute
)

// mtaSTSClient refuses redirects (RFC 8461 §3.3) and verifies the policy host's
// certificate against the system roots.
var mtaSTSClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	},
}

// ResolvePolicy returns the recipient domain's MTA-STS policy, or nil if none is
// published. A non-nil error means discovery itself failed in a way the caller
// should treat as transient; a missing/unparseable policy yields (nil, nil) so
// delivery falls back to opportunistic TLS.
func ResolvePolicy(ctx context.Context, cache PolicyCache, domain string) (*STSPolicy, error) {
	id, ok := lookupSTSID(ctx, domain)
	if !ok {
		return nil, nil
	}

	if cache != nil {
		if p, hit, err := cache.Get(ctx, domain); err == nil && hit && p != nil && p.ID == id {
			return p, nil
		}
	}

	p, maxAge, err := fetchPolicy(ctx, domain)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	p.ID = id

	if cache != nil {
		_ = cache.Put(ctx, domain, p, clampMaxAge(maxAge))
	}
	return p, nil
}

// lookupSTSID reads the _mta-sts.<domain> TXT record and returns its id. A
// missing record (the common case) returns ok=false without surfacing an error.
func lookupSTSID(ctx context.Context, domain string) (id string, ok bool) {
	records, err := net.DefaultResolver.LookupTXT(ctx, "_mta-sts."+domain)
	if err != nil {
		return "", false
	}
	for _, rec := range records {
		var version, recID string
		for _, field := range strings.Split(rec, ";") {
			k, v, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			switch strings.TrimSpace(k) {
			case "v":
				version = strings.TrimSpace(v)
			case "id":
				recID = strings.TrimSpace(v)
			}
		}
		if version == "STSv1" && recID != "" {
			return recID, true
		}
	}
	return "", false
}

func fetchPolicy(ctx context.Context, domain string) (p *STSPolicy, maxAge time.Duration, err error) {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := mtaSTSClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("mta-sts: fetch policy for %s: %w", domain, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("mta-sts: policy for %s returned HTTP status", domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, 0, fmt.Errorf("mta-sts: read policy for %s: %w", domain, err)
	}
	return parsePolicy(string(body))
}

func parsePolicy(body string) (*STSPolicy, time.Duration, error) {
	p := &STSPolicy{}
	var version string
	var maxAge time.Duration
	for _, line := range strings.Split(body, "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "version":
			version = v
		case "mode":
			p.Mode = v
		case "mx":
			if v != "" {
				p.MX = append(p.MX, strings.ToLower(v))
			}
		case "max_age":
			if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
				maxAge = time.Duration(secs) * time.Second
			}
		}
	}
	if version != "STSv1" || p.Mode == "" {
		return nil, 0, nil
	}
	return p, maxAge, nil
}

func clampMaxAge(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return stsMaxAgeFloor
	case d > stsMaxAgeCap:
		return stsMaxAgeCap
	case d < stsMaxAgeFloor:
		return stsMaxAgeFloor
	default:
		return d
	}
}

// policyAllowsMX reports whether mxHost is authorized by the policy's mx
// patterns. A pattern may use a single leading "*." wildcard that matches
// exactly one label (RFC 8461 §4.1). Matching is case-insensitive.
func policyAllowsMX(p *STSPolicy, mxHost string) bool {
	host := strings.ToLower(strings.TrimSuffix(mxHost, "."))
	for _, pattern := range p.MX {
		if matchMXPattern(strings.TrimSuffix(pattern, "."), host) {
			return true
		}
	}
	return false
}

func matchMXPattern(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		// "*." matches exactly one leftmost label, so the remainder after the
		// host's first label must equal the pattern suffix.
		_, rest, found := strings.Cut(host, ".")
		return found && rest == suffix
	}
	return pattern == host
}
