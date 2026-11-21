package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// AbuseIPDBConfig holds optional settings for AbuseIPDB API v2 integration.
type AbuseIPDBConfig struct {
	Enabled           bool   `json:"enabled"`
	APIKey            string `json:"api_key"`
	MaxAgeInDays      int    `json:"max_age_in_days"`
	CacheTTLHours     int    `json:"cache_ttl_hours"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	ReportEnabled     bool   `json:"report_enabled"`
	ReportMinAttempts int    `json:"report_min_attempts"`
}

// IsActive returns true when AbuseIPDB integration is enabled and an API key is configured.
func (a AbuseIPDBConfig) IsActive() bool {
	return a.Enabled && a.APIKey != ""
}

// CacheTTL returns the cache TTL duration for AbuseIPDB lookup results.
func (a AbuseIPDBConfig) CacheTTL() time.Duration {
	return time.Duration(a.CacheTTLHours) * time.Hour
}

// Timeout returns the HTTP timeout duration for AbuseIPDB API requests.
func (a AbuseIPDBConfig) Timeout() time.Duration {
	return time.Duration(a.TimeoutSeconds) * time.Second
}

// Config holds runtime configuration options for ssh-watch-gnome.
type Config struct {
	CooldownSeconds     int             `json:"cooldown_seconds"`
	WhoisCacheTTLHours  int             `json:"whois_cache_ttl_hours"`
	WhoisTimeoutSeconds int             `json:"whois_timeout_seconds"`
	Urgency             byte            `json:"urgency"`
	WhitelistCIDRs      []string        `json:"whitelist_cidrs"`
	AbuseIPDB           AbuseIPDBConfig `json:"abuseipdb"`

	parsedWhitelist []netip.Prefix `json:"-"`
}

// DefaultConfig returns default configuration values as specified in spec.md.
func DefaultConfig() *Config {
	cfg := &Config{
		CooldownSeconds:     60,
		WhoisCacheTTLHours:  24,
		WhoisTimeoutSeconds: 4,
		Urgency:             2, // Critical
		WhitelistCIDRs: []string{
			"127.0.0.1/32",
			"::1/128",
			"192.168.1.0/24",
		},
		AbuseIPDB: AbuseIPDBConfig{
			Enabled:           false,
			APIKey:            "",
			MaxAgeInDays:      90,
			CacheTTLHours:     24,
			TimeoutSeconds:    4,
			ReportEnabled:     false,
			ReportMinAttempts: 3,
		},
	}
	_ = cfg.parseCIDRs()
	return cfg
}

// DefaultConfigPath returns ~/.config/ssh-watch-gnome/config.json.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "ssh-watch-gnome", "config.json")
}

// Load reads and parses the JSON configuration from filePath.
// If filePath is empty, it attempts to load from DefaultConfigPath().
// If the file does not exist, DefaultConfig() is returned.
func Load(filePath string) (*Config, error) {
	if filePath == "" {
		filePath = DefaultConfigPath()
	}

	if filePath == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse json config from %q: %w", filePath, err)
	}

	if cfg.CooldownSeconds <= 0 {
		cfg.CooldownSeconds = 60
	}
	if cfg.WhoisCacheTTLHours <= 0 {
		cfg.WhoisCacheTTLHours = 24
	}
	if cfg.WhoisTimeoutSeconds <= 0 {
		cfg.WhoisTimeoutSeconds = 4
	}
	if cfg.AbuseIPDB.MaxAgeInDays < 1 || cfg.AbuseIPDB.MaxAgeInDays > 365 {
		cfg.AbuseIPDB.MaxAgeInDays = 90
	}
	if cfg.AbuseIPDB.CacheTTLHours <= 0 {
		cfg.AbuseIPDB.CacheTTLHours = 24
	}
	if cfg.AbuseIPDB.TimeoutSeconds <= 0 {
		cfg.AbuseIPDB.TimeoutSeconds = 4
	}
	if cfg.AbuseIPDB.ReportMinAttempts <= 0 {
		cfg.AbuseIPDB.ReportMinAttempts = 3
	}
	if cfg.AbuseIPDB.APIKey == "" {
		cfg.AbuseIPDB.APIKey = os.Getenv("ABUSEIPDB_API_KEY")
	}

	if err := cfg.parseCIDRs(); err != nil {
		return nil, fmt.Errorf("invalid whitelist_cidrs in config: %w", err)
	}

	return cfg, nil
}

// parseCIDRs compiles the string whitelist CIDRs into netip.Prefix slices.
func (c *Config) parseCIDRs() error {
	c.parsedWhitelist = make([]netip.Prefix, 0, len(c.WhitelistCIDRs))
	for _, cidrStr := range c.WhitelistCIDRs {
		prefix, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			// Also support bare IP address notation by converting to /32 or /128
			if addr, parseErr := netip.ParseAddr(cidrStr); parseErr == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			} else {
				return fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
			}
		}
		c.parsedWhitelist = append(c.parsedWhitelist, prefix)
	}
	return nil
}

// IsWhitelisted checks if the provided IP address falls within any configured whitelist CIDR.
func (c *Config) IsWhitelisted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range c.parsedWhitelist {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Cooldown returns the cooldown duration.
func (c *Config) Cooldown() time.Duration {
	return time.Duration(c.CooldownSeconds) * time.Second
}

// WhoisCacheTTL returns the cache TTL duration for WHOIS records.
func (c *Config) WhoisCacheTTL() time.Duration {
	return time.Duration(c.WhoisCacheTTLHours) * time.Hour
}

// WhoisTimeout returns the timeout duration for WHOIS network queries.
func (c *Config) WhoisTimeout() time.Duration {
	return time.Duration(c.WhoisTimeoutSeconds) * time.Second
}
