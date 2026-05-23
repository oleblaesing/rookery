// Package config loads and validates the rookery instance configuration.
// Configuration comes from two sources:
//   - rookery.toml: all non-secret settings (mounted at /etc/rookery/rookery.toml
//     in the container, or at the path given by ROOKERY_CONFIG).
//   - Environment variables: secrets only (ROOKERY_DB_PASSWORD, ROOKERY_MASTER_KEY,
//     ROOKERY_SESSION_KEY). See §11.11 of PLAN.md.
//
// All three secrets and the domain setting are always required.
package config

import (
	"fmt"
	"net/url"
	"os"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration for a rookery instance.
type Config struct {
	// Domain is the primary mail domain for this instance (e.g. "rookery.example").
	// Required.
	Domain string `toml:"domain"`

	// InstanceName is the human-readable display name shown to users on signup
	// pages and in the UI. Defaults to Domain if empty.
	InstanceName string `toml:"instance_name"`

	// ContactEmail is the Let's Encrypt contact address used by the ACME client
	// once TLS is wired up (Phase 4, see §11.7 of PLAN.md). Unused in Phase 0
	// and therefore optional today; populate it ahead of Phase 4 to avoid a
	// later config change.
	ContactEmail string `toml:"contact_email"`

	HTTP    HTTPConfig    `toml:"http"`
	Log     LogConfig     `toml:"log"`
	Storage StorageConfig `toml:"storage"`
	SMTP    SMTPConfig    `toml:"smtp"`
	Policy  PolicyConfig  `toml:"policy"`

	// Secrets loaded from environment variables; never present in the config file.
	Secrets Secrets `toml:"-"`
}

// HTTPConfig controls the HTTP listener.
type HTTPConfig struct {
	// Host is the bind address. Defaults to "0.0.0.0".
	Host string `toml:"host"`

	// Port is the HTTP listener port.
	//
	// Phase 0 serves plaintext HTTP only and defaults to 80. TLS termination
	// via ACME (certmagic) on 443 is a Phase 4 deliverable (§11.7 of PLAN.md);
	// once that lands, the default will move to 443 and port 80 will be kept
	// for ACME HTTP-01 challenges.
	Port int `toml:"port"`
}

// LogConfig controls structured log output.
type LogConfig struct {
	// Level is the minimum log level to emit: "debug", "info", "warn", "error".
	// Defaults to "info".
	Level string `toml:"level"`
}

// StorageConfig configures message file storage.
// Database connectivity is not configurable — rookery always connects to the
// postgres service in the compose stack on the fixed coordinates below.
type StorageConfig struct {
	// MessageDir is the filesystem path where raw .eml message files are
	// stored, content-addressed as messages/sha256/ab/cd/<hash>.eml.
	//
	// This must match the bind mount in compose.yaml. The default
	// ("/var/lib/rookery/messages") is the only path the bundled compose
	// stack mounts the rookery-messages volume at; if you change it here,
	// you must also change the volume mount, or messages will be written
	// to the container's writable layer and lost on container replacement.
	MessageDir string `toml:"message_dir"`
}

// SMTPConfig configures SMTP listener behaviour.
type SMTPConfig struct {
	// MaxMessageBytes is the maximum accepted message size in bytes.
	// Defaults to 26214400 (25 MiB). See §11.4.
	MaxMessageBytes int64 `toml:"max_message_bytes"`

	// OutboundRateLimitPerUser is the maximum outbound messages per hour per user.
	// Defaults to 200. Set explicitly to 0 to disable the limit. See §11.4.
	OutboundRateLimitPerUser int `toml:"outbound_rate_limit_per_user"`

	// OutboundRateLimitPerDomain is the maximum outbound messages per hour against
	// any single destination domain. Defaults to 5000. Set explicitly to 0 to
	// disable the limit. See §11.4.
	OutboundRateLimitPerDomain int `toml:"outbound_rate_limit_per_domain"`

	// OutboundDailyLimitPerUser is the maximum outbound messages per day per user.
	// Defaults to 1000. Set explicitly to 0 to disable the limit. See §11.4.
	OutboundDailyLimitPerUser int `toml:"outbound_daily_limit_per_user"`

	// RelayHost, if non-empty, routes all outbound SMTP deliveries through this
	// relay host instead of direct MX lookup. Useful in development (set to the
	// mailpit service name) or behind a NAT that blocks outbound port 25.
	// Defaults to "" (direct MX delivery).
	RelayHost string `toml:"relay_host"`

	// RelayPort is the SMTP port on RelayHost. Defaults to 25.
	RelayPort int `toml:"relay_port"`
}

// PolicyConfig controls per-instance policy toggles.
type PolicyConfig struct {
	// DefaultQuotaBytes is the default per-user mailbox quota in bytes.
	// Defaults to 5368709120 (5 GiB). Set explicitly to 0 to disable the
	// per-user quota cap entirely. See §11.5.
	DefaultQuotaBytes int64 `toml:"default_quota_bytes"`

	// TrashRetentionDays is how long messages in Trash are kept before hard
	// deletion. Defaults to 30. Set explicitly to 0 for immediate hard delete
	// on trash. See §11.5.
	TrashRetentionDays int `toml:"trash_retention_days"`

	// SessionExpiryDays is how long a session remains valid after last use.
	// Defaults to 7. See §11.2.
	SessionExpiryDays int `toml:"session_expiry_days"`

	// LogConnectingIPs enables logging of connecting IP addresses on the web UI
	// and submission ports. Off by default for pseudonymity. See §5.4, §11.2.
	LogConnectingIPs bool `toml:"log_connecting_ips"`
}

// Secrets holds values that come from environment variables, never from the
// config file. Missing required secrets cause Load to return an error.
type Secrets struct {
	// DBPassword is the Postgres password. From ROOKERY_DB_PASSWORD.
	// The server constructs the full connection URL from this plus the
	// [storage] settings in rookery.toml.
	DBPassword string

	// MasterKey is the server master key used to encrypt DKIM private keys,
	// session secrets, and ACME account keys at rest. From ROOKERY_MASTER_KEY.
	// See §11.6.
	MasterKey string

	// SessionKey is the HMAC key for session cookie signing. From
	// ROOKERY_SESSION_KEY. See §11.2.
	SessionKey string
}

// defaults fills in any field the operator did not set in the TOML file. It
// uses toml.MetaData rather than zero-value checks so that an explicit "0" in
// the config is preserved as a meaningful value (for rate limits, quota, and
// trash retention; see the field docs above).
func defaults(c *Config, md toml.MetaData) {
	if c.InstanceName == "" {
		c.InstanceName = c.Domain
	}
	if !md.IsDefined("http", "host") {
		c.HTTP.Host = "0.0.0.0"
	}
	if !md.IsDefined("http", "port") {
		c.HTTP.Port = 80
	}
	if !md.IsDefined("log", "level") {
		c.Log.Level = "info"
	}
	if !md.IsDefined("storage", "message_dir") {
		c.Storage.MessageDir = "/var/lib/rookery/messages"
	}
	if !md.IsDefined("smtp", "max_message_bytes") {
		c.SMTP.MaxMessageBytes = 25 * 1024 * 1024 // 25 MiB
	}
	if !md.IsDefined("smtp", "outbound_rate_limit_per_user") {
		c.SMTP.OutboundRateLimitPerUser = 200
	}
	if !md.IsDefined("smtp", "outbound_rate_limit_per_domain") {
		c.SMTP.OutboundRateLimitPerDomain = 5000
	}
	if !md.IsDefined("smtp", "outbound_daily_limit_per_user") {
		c.SMTP.OutboundDailyLimitPerUser = 1000
	}
	if !md.IsDefined("smtp", "relay_port") {
		c.SMTP.RelayPort = 25
	}
	if !md.IsDefined("policy", "default_quota_bytes") {
		c.Policy.DefaultQuotaBytes = 5 * 1024 * 1024 * 1024 // 5 GiB
	}
	if !md.IsDefined("policy", "trash_retention_days") {
		c.Policy.TrashRetentionDays = 30
	}
	if !md.IsDefined("policy", "session_expiry_days") {
		c.Policy.SessionExpiryDays = 7
	}
}

// Load reads the config file at path and merges secrets from environment
// variables. It returns an error if any required value is missing or empty.
//
// The config file is optional — if the file does not exist, built-in defaults
// apply for every non-secret setting. The three secrets (ROOKERY_DB_PASSWORD,
// ROOKERY_MASTER_KEY, ROOKERY_SESSION_KEY) and the domain setting are always
// required; the server refuses to start without them.
func Load(path string) (*Config, error) {
	var cfg Config
	var md toml.MetaData

	if _, err := os.Stat(path); err == nil {
		var derr error
		md, derr = toml.DecodeFile(path, &cfg)
		if derr != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, derr)
		}
	}

	defaults(&cfg, md)

	cfg.Secrets.DBPassword = os.Getenv("ROOKERY_DB_PASSWORD")
	cfg.Secrets.MasterKey = os.Getenv("ROOKERY_MASTER_KEY")
	cfg.Secrets.SessionKey = os.Getenv("ROOKERY_SESSION_KEY")

	if cfg.Domain == "" {
		return nil, fmt.Errorf("config: domain is required (set in rookery.toml)")
	}
	if cfg.Secrets.DBPassword == "" {
		return nil, fmt.Errorf("env: ROOKERY_DB_PASSWORD is required")
	}
	if cfg.Secrets.MasterKey == "" {
		return nil, fmt.Errorf("env: ROOKERY_MASTER_KEY is required")
	}
	if cfg.Secrets.SessionKey == "" {
		return nil, fmt.Errorf("env: ROOKERY_SESSION_KEY is required")
	}

	return &cfg, nil
}

// DBUrl returns the Postgres connection URL. The coordinates are fixed —
// rookery always connects to the postgres service in the compose stack.
//
// The password is URL-encoded so that passwords containing reserved characters
// (@, /, :, #, ?, %, …) round-trip correctly. The bundled secrets-init
// generates hex-only passwords, but operators can supply their own.
func (c *Config) DBUrl() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("rookery", c.Secrets.DBPassword),
		Host:     "postgres:5432",
		Path:     "/rookery",
		RawQuery: "sslmode=disable",
	}
	return u.String()
}
