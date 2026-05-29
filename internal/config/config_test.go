package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes body to a temp rookery.toml and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rookery.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// setBaseSecrets sets the always-required secret env vars (and clears the
// smarthost password unless a test sets it). Uses t.Setenv so values are
// restored after the test.
func setBaseSecrets(t *testing.T) {
	t.Helper()
	t.Setenv("ROOKERY_DB_PASSWORD", "db")
	t.Setenv("ROOKERY_MASTER_KEY", "mk")
	t.Setenv("ROOKERY_SESSION_KEY", "sk")
	t.Setenv("ROOKERY_SMTP_RELAY_PASSWORD", "")
}

func TestSmarthostDefaults(t *testing.T) {
	setBaseSecrets(t)
	path := writeConfig(t, `domain = "rookery.example"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sh := cfg.SMTP.Smarthost
	if sh.Enabled {
		t.Error("smarthost should be disabled by default")
	}
	if sh.Port != 587 {
		t.Errorf("default port = %d, want 587", sh.Port)
	}
	if !sh.RequireTLS {
		t.Error("require_tls should default to true")
	}
	if !sh.Auth {
		t.Error("auth should default to true")
	}
}

func TestSmarthostRoundTripAndExplicitFalse(t *testing.T) {
	setBaseSecrets(t)
	t.Setenv("ROOKERY_SMTP_RELAY_PASSWORD", "pw")
	path := writeConfig(t, `
domain = "rookery.example"
[smtp.smarthost]
enabled     = true
host        = "smtp.postmarkapp.com"
port        = 465
username    = "token-id"
require_tls = false
auth        = false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sh := cfg.SMTP.Smarthost
	if !sh.Enabled || sh.Host != "smtp.postmarkapp.com" || sh.Port != 465 || sh.Username != "token-id" {
		t.Errorf("round-trip mismatch: %+v", sh)
	}
	// Explicit false must survive the default-filling (md.IsDefined) logic.
	if sh.RequireTLS {
		t.Error("explicit require_tls = false was overwritten by the default")
	}
	if sh.Auth {
		t.Error("explicit auth = false was overwritten by the default")
	}
}

func TestSmarthostValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		relayPW string
		wantErr bool
	}{
		{
			name:    "enabled without host",
			body:    "domain = \"rookery.example\"\n[smtp.smarthost]\nenabled = true\nauth = false\nrequire_tls = false\n",
			wantErr: true,
		},
		{
			name:    "auth without username",
			body:    "domain = \"rookery.example\"\n[smtp.smarthost]\nenabled = true\nhost = \"h\"\n",
			relayPW: "pw",
			wantErr: true,
		},
		{
			name:    "auth without password env",
			body:    "domain = \"rookery.example\"\n[smtp.smarthost]\nenabled = true\nhost = \"h\"\nusername = \"u\"\n",
			wantErr: true,
		},
		{
			name:    "valid authed smarthost",
			body:    "domain = \"rookery.example\"\n[smtp.smarthost]\nenabled = true\nhost = \"h\"\nusername = \"u\"\n",
			relayPW: "pw",
			wantErr: false,
		},
		{
			name:    "valid no-auth mailpit shape",
			body:    "domain = \"rookery.example\"\n[smtp.smarthost]\nenabled = true\nhost = \"mailpit\"\nport = 1025\nauth = false\nrequire_tls = false\n",
			wantErr: false,
		},
		{
			name:    "disabled smarthost ignores missing fields",
			body:    "domain = \"rookery.example\"\n[smtp.smarthost]\nenabled = false\n",
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setBaseSecrets(t)
			if tc.relayPW != "" {
				t.Setenv("ROOKERY_SMTP_RELAY_PASSWORD", tc.relayPW)
			}
			_, err := Load(writeConfig(t, tc.body))
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
