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
	"log/slog"
	"net/url"
	"os"
	"strings"

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
	DNS     DNSConfig     `toml:"dns"`
	Spam    SpamConfig    `toml:"spam"`

	// Secrets loaded from environment variables; never present in the config file.
	Secrets Secrets `toml:"-"`
}

// HTTPConfig controls the HTTP listener.
type HTTPConfig struct {
	// Host is the bind address. Defaults to "0.0.0.0".
	Host string `toml:"host"`

	// Port is the HTTP listener port. Defaults to 8080.
	//
	// In production, Caddy (or another reverse proxy) handles TLS termination
	// and forwards plain HTTP to rookery on this port. In development you hit
	// this port directly in your browser. Change it only if 8080 conflicts with
	// something else on your host.
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

	// Smarthost configures routing all outbound mail through an upstream SMTP
	// submission endpoint instead of direct MX delivery. See ADR-0030.
	Smarthost SmarthostConfig `toml:"smarthost"`
}

// SmarthostConfig configures an outbound smarthost: a trusted upstream SMTP
// submission endpoint (a commercial relay like SES/Postmark/Mailgun, another
// rookery instance acting as a relay, or mailpit in development) through which
// all outbound mail is routed. rookery DKIM-signs every message before handoff;
// the smarthost is opaque transport. See ADR-0030 and §11.10 of PLAN.md.
//
// The dev-only relay_host/relay_port mechanism was folded into this block:
// capturing outbound in mailpit is just a smarthost with Auth and RequireTLS
// turned off.
type SmarthostConfig struct {
	// Enabled routes all outbound through the smarthost when true. When false
	// (the default), rookery does direct MX delivery.
	Enabled bool `toml:"enabled"`

	// Host is the smarthost's hostname. Required when Enabled.
	Host string `toml:"host"`

	// Port is the submission port. Defaults to 587 (STARTTLS). Use 465 for
	// implicit TLS.
	Port int `toml:"port"`

	// Username is the SASL username. Required when Auth.
	Username string `toml:"username"`

	// RequireTLS enforces TLS for the session (mandatory STARTTLS on 587;
	// implicit TLS on 465). Defaults to true. A smarthost session carries AUTH
	// credentials, so unlike opportunistic MX delivery, a failure to establish
	// TLS aborts the attempt rather than sending plaintext. Set to false only
	// for a trusted no-TLS endpoint such as dev mailpit.
	RequireTLS bool `toml:"require_tls"`

	// Auth enables SASL authentication. Defaults to true. Set to false only for
	// an unauthenticated endpoint such as dev mailpit. The password comes from
	// the ROOKERY_SMTP_RELAY_PASSWORD environment variable, never the file.
	Auth bool `toml:"auth"`
}

// SpamConfig controls spam filtering via rspamd.
type SpamConfig struct {
	// RspamdURL is the base URL of the rspamd HTTP check API.
	// Default: "http://rspamd:11333" (the bundled rspamd container).
	// Set to "" to disable spam checking entirely.
	RspamdURL string `toml:"rspamd_url"`
}

// DNSConfig controls DNS resolver settings used for domain verification and
// drift detection. The resolver defaults to Quad9 (9.9.9.9:53) for privacy.
type DNSConfig struct {
	// Resolver is the DNS server address (host:port) used for domain verification
	// and drift-detection checks. Defaults to "9.9.9.9:53" (Quad9). Set to ""
	// to use the system resolver.
	Resolver string `toml:"resolver"`
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

	// SMTPRelayPassword is the SASL password for the outbound smarthost. From
	// ROOKERY_SMTP_RELAY_PASSWORD. Required iff [smtp.smarthost] has both
	// enabled and auth set. See §11.11 and ADR-0030.
	SMTPRelayPassword string
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
		c.HTTP.Port = 8080
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
	if !md.IsDefined("smtp", "smarthost", "port") {
		c.SMTP.Smarthost.Port = 587
	}
	if !md.IsDefined("smtp", "smarthost", "require_tls") {
		c.SMTP.Smarthost.RequireTLS = true
	}
	if !md.IsDefined("smtp", "smarthost", "auth") {
		c.SMTP.Smarthost.Auth = true
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
	if !md.IsDefined("dns", "resolver") {
		c.DNS.Resolver = "9.9.9.9:53"
	}
	if !md.IsDefined("spam", "rspamd_url") {
		c.Spam.RspamdURL = "http://rspamd:11333"
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
	cfg.Secrets.SMTPRelayPassword = os.Getenv("ROOKERY_SMTP_RELAY_PASSWORD")

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

	if err := validateSmarthost(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateSmarthost checks the [smtp.smarthost] block for internal consistency
// when it is enabled, and logs a warning if TLS is disabled (a credential-
// bearing session over plaintext). It is a no-op when the smarthost is off.
func validateSmarthost(cfg *Config) error {
	sh := &cfg.SMTP.Smarthost
	if !sh.Enabled {
		return nil
	}
	if sh.Host == "" {
		return fmt.Errorf("config: [smtp.smarthost] host is required when enabled")
	}
	if sh.Auth {
		if sh.Username == "" {
			return fmt.Errorf("config: [smtp.smarthost] username is required when auth is enabled")
		}
		if cfg.Secrets.SMTPRelayPassword == "" {
			return fmt.Errorf("env: ROOKERY_SMTP_RELAY_PASSWORD is required when [smtp.smarthost] auth is enabled")
		}
	}
	if !sh.RequireTLS {
		slog.Warn("config: [smtp.smarthost] require_tls is false — outbound mail (and any SASL credentials) will be sent without enforced TLS",
			"host", sh.Host)
	}
	return nil
}

// ExternalURL returns the base URL used in links sent to users.
//   - localhost / *.localhost → http:// with port when non-80
//   - everything else         → https:// with no port (Caddy owns 443)
func (c *Config) ExternalURL() string {
	d := c.Domain
	if d == "localhost" || strings.HasSuffix(d, ".localhost") {
		if c.HTTP.Port != 80 {
			return fmt.Sprintf("http://%s:%d", d, c.HTTP.Port)
		}
		return "http://" + d
	}
	return "https://" + d
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
