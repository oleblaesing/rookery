package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Domain       string `toml:"domain"`
	InstanceName string `toml:"instance_name"`
	ContactEmail string `toml:"contact_email"`

	// Bare hostname advertised to clearnet visitors via Onion-Location so Tor
	// Browser can offer the onion. rookery does not run Tor itself; only the web
	// UI is reachable over it, mail stays on the clearnet domain.
	OnionAddress string `toml:"onion_address"`

	HTTP    HTTPConfig    `toml:"http"`
	Log     LogConfig     `toml:"log"`
	Storage StorageConfig `toml:"storage"`
	SMTP    SMTPConfig    `toml:"smtp"`
	Policy  PolicyConfig  `toml:"policy"`
	DNS     DNSConfig     `toml:"dns"`
	Spam    SpamConfig    `toml:"spam"`

	Secrets Secrets `toml:"-"`
}

type HTTPConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

type LogConfig struct {
	Level string `toml:"level"`
}

type StorageConfig struct {
	// Must match the messages-data volume mount in compose.yaml, otherwise
	// messages land on the container's writable layer and are lost on replace.
	MessageDir string `toml:"message_dir"`
}

type SMTPConfig struct {
	MaxMessageBytes            int64 `toml:"max_message_bytes"`
	OutboundRateLimitPerUser   int   `toml:"outbound_rate_limit_per_user"`
	OutboundRateLimitPerDomain int   `toml:"outbound_rate_limit_per_domain"`
	OutboundDailyLimitPerUser  int   `toml:"outbound_daily_limit_per_user"`

	Smarthost SmarthostConfig `toml:"smarthost"`

	SubmissionEnabled  bool   `toml:"submission_enabled"`
	SubmissionCertsDir string `toml:"submission_certs_dir"`
	SubmissionCertFile string `toml:"submission_cert_file"`
	SubmissionKeyFile  string `toml:"submission_key_file"`
}

type SmarthostConfig struct {
	Enabled  bool   `toml:"enabled"`
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`

	// A smarthost session carries AUTH credentials, so a TLS failure aborts
	// rather than falling back to plaintext. Disable only for dev mailpit.
	RequireTLS bool `toml:"require_tls"`

	Auth bool `toml:"auth"`
}

type SpamConfig struct {
	RspamdURL string `toml:"rspamd_url"`
}

type DNSConfig struct {
	Resolver string `toml:"resolver"`
}

type PolicyConfig struct {
	DefaultQuotaBytes  int64 `toml:"default_quota_bytes"`
	TrashRetentionDays int   `toml:"trash_retention_days"`
	SessionExpiryDays  int   `toml:"session_expiry_days"`
	LogConnectingIPs   bool  `toml:"log_connecting_ips"`
}

type Secrets struct {
	DBPassword        string
	MasterKey         string
	SessionKey        string
	SMTPRelayPassword string
}

// Uses md.IsDefined rather than zero-value checks so an explicit 0 in the config
// (rate limits, quota, trash retention) survives instead of being overwritten.
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
		c.SMTP.MaxMessageBytes = 25 * 1024 * 1024
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
	if !md.IsDefined("smtp", "submission_certs_dir") {
		c.SMTP.SubmissionCertsDir = "/data/caddy/certificates"
	}
	if !md.IsDefined("policy", "default_quota_bytes") {
		c.Policy.DefaultQuotaBytes = 5 * 1024 * 1024 * 1024
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
	if err := validateOnionAddress(&cfg); err != nil {
		return nil, err
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
	if err := validateSubmission(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Requires a bare hostname so the web layer can build the Onion-Location header
// as scheme + host + request path.
func validateOnionAddress(cfg *Config) error {
	a := cfg.OnionAddress
	if a == "" {
		return nil
	}
	if strings.Contains(a, "/") || strings.Contains(a, "://") {
		return fmt.Errorf("config: onion_address must be a bare hostname, not a URL (got %q)", a)
	}
	if !strings.HasSuffix(a, ".onion") {
		return fmt.Errorf("config: onion_address must end in .onion (got %q)", a)
	}
	return nil
}

func validateSubmission(cfg *Config) error {
	s := &cfg.SMTP
	if !s.SubmissionEnabled {
		return nil
	}
	// A half-configured cert pair is a typo, not a fallback to the Caddy dir.
	if (s.SubmissionCertFile == "") != (s.SubmissionKeyFile == "") {
		return fmt.Errorf("config: [smtp] submission_cert_file and submission_key_file must both be set or both be empty")
	}
	if s.SubmissionCertFile == "" && s.SubmissionCertsDir == "" {
		return fmt.Errorf("config: [smtp] submission_certs_dir is required when submission_enabled (or set explicit submission_cert_file/key_file)")
	}
	return nil
}

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

// http with port for localhost, https otherwise (Caddy owns 443).
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

func (c *Config) DBUrl() string {
	// Password is URL-encoded so reserved characters (@ / : # ? %) round-trip.
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("rookery", c.Secrets.DBPassword),
		Host:     "postgres:5432",
		Path:     "/rookery",
		RawQuery: "sslmode=disable",
	}
	return u.String()
}
