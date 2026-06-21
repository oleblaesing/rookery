package smtp

import (
	"testing"
	"time"
)

func TestParsePolicy(t *testing.T) {
	body := "version: STSv1\r\n" +
		"mode: enforce\r\n" +
		"mx: mail.example.com\r\n" +
		"mx: *.example.net\r\n" +
		"max_age: 604800\r\n" +
		"future_key: ignored\r\n"

	p, maxAge, err := parsePolicy(body)
	if err != nil {
		t.Fatalf("parsePolicy: %v", err)
	}
	if p == nil {
		t.Fatal("parsePolicy returned nil for a valid policy")
	}
	if p.Mode != "enforce" {
		t.Errorf("Mode = %q, want enforce", p.Mode)
	}
	if len(p.MX) != 2 || p.MX[0] != "mail.example.com" || p.MX[1] != "*.example.net" {
		t.Errorf("MX = %v, want [mail.example.com *.example.net]", p.MX)
	}
	if maxAge != 604800*time.Second {
		t.Errorf("maxAge = %v, want 604800s", maxAge)
	}
}

func TestParsePolicy_Invalid(t *testing.T) {
	cases := map[string]string{
		"missing version": "mode: enforce\nmx: a.example.com\n",
		"wrong version":   "version: STSv2\nmode: enforce\n",
		"missing mode":    "version: STSv1\nmx: a.example.com\n",
		"empty":           "",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p, _, err := parsePolicy(body)
			if err != nil {
				t.Fatalf("parsePolicy: %v", err)
			}
			if p != nil {
				t.Errorf("expected nil policy, got %+v", p)
			}
		})
	}
}

func TestPolicyAllowsMX(t *testing.T) {
	p := &STSPolicy{MX: []string{"mail.example.com", "*.example.net"}}
	cases := []struct {
		host string
		want bool
	}{
		{"mail.example.com", true},
		{"MAIL.EXAMPLE.COM", true}, // case-insensitive
		{"mail.example.com.", true}, // trailing dot tolerated
		{"mx1.example.net", true},   // wildcard, one label
		{"a.b.example.net", false},  // wildcard matches only one label
		{"example.net", false},      // wildcard requires a label
		{"mail.example.org", false},
	}
	for _, c := range cases {
		if got := policyAllowsMX(p, c.host); got != c.want {
			t.Errorf("policyAllowsMX(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestClampMaxAge(t *testing.T) {
	if got := clampMaxAge(0); got != stsMaxAgeFloor {
		t.Errorf("clampMaxAge(0) = %v, want floor %v", got, stsMaxAgeFloor)
	}
	if got := clampMaxAge(48 * time.Hour); got != stsMaxAgeCap {
		t.Errorf("clampMaxAge(48h) = %v, want cap %v", got, stsMaxAgeCap)
	}
	if got := clampMaxAge(time.Hour); got != time.Hour {
		t.Errorf("clampMaxAge(1h) = %v, want 1h", got)
	}
}
