package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-watch-gnome/internal/config"
	"ssh-watch-gnome/internal/limiter"
	"ssh-watch-gnome/internal/logwatcher"
	"ssh-watch-gnome/internal/whois"
)

type mockNotifier struct {
	mu            sync.Mutex
	notifications []string
}

func (m *mockNotifier) Notify(ctx context.Context, ip, country, user, org string, attempts int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifications = append(m.notifications, fmt.Sprintf("%s (%s) - %s - %d attempts", ip, country, org, attempts))
	return nil
}

func (m *mockNotifier) Close() error {
	return nil
}

func TestEndToEndPipeline(t *testing.T) {
	// Whitelist: 192.168.1.0/24 and 127.0.0.1/32
	cfg := config.DefaultConfig()
	cfg.CooldownSeconds = 1 // 1 second cooldown for test

	lim := limiter.New(cfg.Cooldown())
	mockQuery := func(ctx context.Context, ip string) (string, error) {
		return "OrgName: Test ISP\nCountry: ES\nOriginAS: AS12345\n", nil
	}
	whoisClient := whois.NewClient(cfg.WhoisTimeout(), cfg.WhoisCacheTTL(), mockQuery)
	mockNotif := &mockNotifier{}

	// Generate 50 repeated failed attempts for public IP 203.0.113.10
	// Plus 5 attempts from a whitelisted IP 192.168.1.50
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteString("Failed password for invalid user hacker from 203.0.113.10 port 45123 ssh2\n")
	}
	for i := 0; i < 5; i++ {
		sb.WriteString("Failed password for root from 192.168.1.50 port 22 ssh2\n")
	}

	eventsChan := make(chan logwatcher.SSHEvent, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = logwatcher.StreamReader(ctx, strings.NewReader(sb.String()), eventsChan)
		close(eventsChan)
	}()

	var alertWg sync.WaitGroup

	for ev := range eventsChan {
		if cfg.IsWhitelisted(ev.IP) {
			continue
		}

		shouldNotify, attempts := lim.Record(ev.IP)
		if !shouldNotify {
			continue
		}

		alertWg.Add(1)
		go func(event logwatcher.SSHEvent, totalAttempts int) {
			defer alertWg.Done()
			info, _ := whoisClient.Lookup(ctx, event.IP)
			country := ""
			org := ""
			if info != nil {
				country = info.Country
				org = info.DisplayOrg()
			}
			_ = mockNotif.Notify(ctx, event.IP.String(), country, event.User, org, totalAttempts)
		}(ev, attempts)
	}

	alertWg.Wait()

	mockNotif.mu.Lock()
	defer mockNotif.mu.Unlock()

	// Should have recorded exactly 1 notification for 203.0.113.10, and 0 for 192.168.1.50
	if len(mockNotif.notifications) != 1 {
		t.Fatalf("expected exactly 1 notification, got %d: %+v", len(mockNotif.notifications), mockNotif.notifications)
	}

	expectedPrefix := "203.0.113.10 (ES) - Test ISP (AS12345)"
	if !strings.HasPrefix(mockNotif.notifications[0], expectedPrefix) {
		t.Errorf("expected notification to start with %q, got %q", expectedPrefix, mockNotif.notifications[0])
	}

	// Verify that the limiter recorded all 50 attempts for 203.0.113.10
	if lim.GetAttempts(netip.MustParseAddr("203.0.113.10")) != 50 {
		t.Errorf("expected 50 attempts recorded in limiter, got %d", lim.GetAttempts(netip.MustParseAddr("203.0.113.10")))
	}
}
