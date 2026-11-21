package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CooldownSeconds != 60 {
		t.Fatalf("expected CooldownSeconds=60, got %d", cfg.CooldownSeconds)
	}
	if cfg.WhoisCacheTTLHours != 24 {
		t.Fatalf("expected WhoisCacheTTLHours=24, got %d", cfg.WhoisCacheTTLHours)
	}
	if cfg.WhoisTimeoutSeconds != 4 {
		t.Fatalf("expected WhoisTimeoutSeconds=4, got %d", cfg.WhoisTimeoutSeconds)
	}
	if cfg.Urgency != 2 {
		t.Fatalf("expected Urgency=2, got %d", cfg.Urgency)
	}

	// Test localhost IPv4 and IPv6
	addrV4 := netip.MustParseAddr("127.0.0.1")
	if !cfg.IsWhitelisted(addrV4) {
		t.Errorf("expected 127.0.0.1 to be whitelisted by default")
	}

	addrV6 := netip.MustParseAddr("::1")
	if !cfg.IsWhitelisted(addrV6) {
		t.Errorf("expected ::1 to be whitelisted by default")
	}

	publicIP := netip.MustParseAddr("203.0.113.1")
	if cfg.IsWhitelisted(publicIP) {
		t.Errorf("expected 203.0.113.1 NOT to be whitelisted")
	}
}

func TestLoadConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "config.json")

	content := `{
		"cooldown_seconds": 30,
		"whois_cache_ttl_hours": 12,
		"whois_timeout_seconds": 5,
		"urgency": 1,
		"whitelist_cidrs": [
			"10.0.0.0/8",
			"192.168.0.1"
		]
	}`

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.CooldownSeconds != 30 {
		t.Errorf("expected CooldownSeconds=30, got %d", cfg.CooldownSeconds)
	}
	if cfg.WhoisCacheTTLHours != 12 {
		t.Errorf("expected WhoisCacheTTLHours=12, got %d", cfg.WhoisCacheTTLHours)
	}
	if cfg.WhoisTimeoutSeconds != 5 {
		t.Errorf("expected WhoisTimeoutSeconds=5, got %d", cfg.WhoisTimeoutSeconds)
	}
	if cfg.Urgency != 1 {
		t.Errorf("expected Urgency=1, got %d", cfg.Urgency)
	}

	// 10.1.2.3 should be whitelisted
	if !cfg.IsWhitelisted(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("expected 10.1.2.3 to be whitelisted")
	}

	// 192.168.0.1 bare IP should be whitelisted
	if !cfg.IsWhitelisted(netip.MustParseAddr("192.168.0.1")) {
		t.Errorf("expected 192.168.0.1 to be whitelisted")
	}

	// 192.168.0.2 should NOT be whitelisted
	if cfg.IsWhitelisted(netip.MustParseAddr("192.168.0.2")) {
		t.Errorf("expected 192.168.0.2 NOT to be whitelisted")
	}
}

func TestLoadAbuseIPDBConfigAndEnvFallback(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "config.json")

	content := `{
		"abuseipdb": {
			"enabled": true,
			"max_age_in_days": 60,
			"cache_ttl_hours": 12,
			"timeout_seconds": 5,
			"report_enabled": true,
			"report_min_attempts": 5
		}
	}`

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Setenv("ABUSEIPDB_API_KEY", "env-secret-key")

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if !cfg.AbuseIPDB.IsActive() {
		t.Fatalf("expected AbuseIPDB to be active with env fallback key")
	}
	if cfg.AbuseIPDB.APIKey != "env-secret-key" {
		t.Errorf("expected APIKey from env, got %q", cfg.AbuseIPDB.APIKey)
	}
	if cfg.AbuseIPDB.MaxAgeInDays != 60 {
		t.Errorf("expected MaxAgeInDays=60, got %d", cfg.AbuseIPDB.MaxAgeInDays)
	}
	if cfg.AbuseIPDB.CacheTTLHours != 12 {
		t.Errorf("expected CacheTTLHours=12, got %d", cfg.AbuseIPDB.CacheTTLHours)
	}
	if cfg.AbuseIPDB.TimeoutSeconds != 5 {
		t.Errorf("expected TimeoutSeconds=5, got %d", cfg.AbuseIPDB.TimeoutSeconds)
	}
	if !cfg.AbuseIPDB.ReportEnabled || cfg.AbuseIPDB.ReportMinAttempts != 5 {
		t.Errorf("unexpected report config: %+v", cfg.AbuseIPDB)
	}
}
