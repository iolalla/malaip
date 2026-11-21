package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"ssh-watch-gnome/internal/abuseipdb"
	"ssh-watch-gnome/internal/config"
	"ssh-watch-gnome/internal/limiter"
	"ssh-watch-gnome/internal/logwatcher"
	"ssh-watch-gnome/internal/notifier"
	"ssh-watch-gnome/internal/whois"
)

type mockNotifier struct {
	mu            sync.Mutex
	notifications []string
}

func (m *mockNotifier) Notify(ctx context.Context, alert notifier.Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifications = append(m.notifications, fmt.Sprintf("%s (%s) - %s - [%s] - %d attempts",
		alert.IP, alert.Country, alert.Org, alert.AbuseSummary, alert.Attempts))
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

	abuseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ipAddress":"203.0.113.10","abuseConfidenceScore":95,"countryCode":"ES","isp":"Test ISP","totalReports":12}}`))
	}))
	defer abuseSrv.Close()

	abuseClient := abuseipdb.NewClient("test-key", 90, 2*time.Second, time.Hour, abuseSrv.Client())
	abuseClient.SetBaseURL(abuseSrv.URL)

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
			abuseRes, _ := abuseClient.Check(ctx, event.IP)
			country := ""
			org := ""
			if info != nil {
				country = info.Country
				org = info.DisplayOrg()
			}
			_ = mockNotif.Notify(ctx, notifier.Alert{
				IP:           event.IP.String(),
				Country:      country,
				User:         event.User,
				Org:          org,
				AbuseSummary: abuseRes.FormatSummary(),
				Attempts:     totalAttempts,
			})
		}(ev, attempts)
	}

	alertWg.Wait()

	mockNotif.mu.Lock()
	defer mockNotif.mu.Unlock()

	// Should have recorded exactly 1 notification for 203.0.113.10, and 0 for 192.168.1.50
	if len(mockNotif.notifications) != 1 {
		t.Fatalf("expected exactly 1 notification, got %d: %+v", len(mockNotif.notifications), mockNotif.notifications)
	}

	expectedPrefix := "203.0.113.10 (ES) - Test ISP (AS12345) - [95% confianza (12 reportes)]"
	if !strings.HasPrefix(mockNotif.notifications[0], expectedPrefix) {
		t.Errorf("expected notification to start with %q, got %q", expectedPrefix, mockNotif.notifications[0])
	}

	// Verify that the limiter recorded all 50 attempts for 203.0.113.10
	if lim.GetAttempts(netip.MustParseAddr("203.0.113.10")) != 50 {
		t.Errorf("expected 50 attempts recorded in limiter, got %d", lim.GetAttempts(netip.MustParseAddr("203.0.113.10")))
	}
}
