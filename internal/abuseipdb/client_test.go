package abuseipdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckSuccessAndCache(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/check" {
			t.Errorf("expected path /check, got %s", r.URL.Path)
		}
		if gotKey := r.Header.Get("Key"); gotKey != "test-api-key" {
			t.Errorf("expected Key header 'test-api-key', got %q", gotKey)
		}
		if gotIP := r.URL.Query().Get("ipAddress"); gotIP != "203.0.113.45" {
			t.Errorf("expected ipAddress=203.0.113.45, got %q", gotIP)
		}
		if gotAge := r.URL.Query().Get("maxAgeInDays"); gotAge != "90" {
			t.Errorf("expected maxAgeInDays=90, got %q", gotAge)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"ipAddress": "203.0.113.45",
				"isPublic": true,
				"abuseConfidenceScore": 87,
				"countryCode": "CN",
				"usageType": "Data Center/Web Hosting/Transit",
				"isp": "China Telecom",
				"domain": "chinatelecom.com.cn",
				"isTor": true,
				"isWhitelisted": false,
				"totalReports": 42
			}
		}`))
	}))
	defer srv.Close()

	client := NewClient("test-api-key", 90, 2*time.Second, 1*time.Hour, srv.Client())
	client.SetBaseURL(srv.URL)

	ip := netip.MustParseAddr("203.0.113.45")
	res1, err := client.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error on first check: %v", err)
	}
	if res1.AbuseConfidenceScore != 87 || res1.TotalReports != 42 || res1.CountryCode != "CN" || !res1.IsTor {
		t.Fatalf("unexpected check result: %+v", res1)
	}
	if got := res1.FormatSummary(); got != "87% confianza (42 reportes) [Tor]" {
		t.Errorf("unexpected summary: %q", got)
	}

	// Second call should hit cache and not perform HTTP request
	res2, err := client.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error on cached check: %v", err)
	}
	if res2.AbuseConfidenceScore != 87 {
		t.Errorf("expected cached score 87, got %d", res2.AbuseConfidenceScore)
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 HTTP hit due to caching, got %d", hits.Load())
	}
}

func TestCheckIPv6AndRateLimitErrorNotCached(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if gotIP := r.URL.Query().Get("ipAddress"); gotIP != "2001:db8::1" {
			t.Errorf("expected decoded IPv6 2001:db8::1, got %q", gotIP)
		}
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ipAddress":"2001:db8::1","abuseConfidenceScore":10,"totalReports":1}}`))
	}))
	defer srv.Close()

	client := NewClient("key", 30, 2*time.Second, 1*time.Hour, srv.Client())
	client.SetBaseURL(srv.URL)

	ip := netip.MustParseAddr("2001:db8::1")
	if _, err := client.Check(context.Background(), ip); err == nil {
		t.Fatalf("expected error on HTTP 429")
	}

	// Subsequent call must retry since 429 is not cached
	res, err := client.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("expected second check to succeed, got: %v", err)
	}
	if got := res.FormatSummary(); got != "10% confianza (1 reporte)" {
		t.Errorf("unexpected singular summary: %q", got)
	}
	if hits.Load() != 2 {
		t.Errorf("expected 2 HTTP hits, got %d", hits.Load())
	}
}

func TestReportAndCooldown(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
		}
		if r.PostForm.Get("ip") != "198.51.100.22" {
			t.Errorf("unexpected ip: %q", r.PostForm.Get("ip"))
		}
		if r.PostForm.Get("categories") != "18,22" {
			t.Errorf("unexpected categories: %q", r.PostForm.Get("categories"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"ipAddress":"198.51.100.22","abuseConfidenceScore":100}}`))
	}))
	defer srv.Close()

	client := NewClient("key", 90, 2*time.Second, 1*time.Hour, srv.Client())
	client.SetBaseURL(srv.URL)
	client.SetReportCooldown(15 * time.Minute)

	ip := netip.MustParseAddr("198.51.100.22")

	sent, err := client.Report(context.Background(), ip, "SSH brute-force attempt for user root")
	if err != nil || !sent {
		t.Fatalf("expected first report to succeed, sent=%v err=%v", sent, err)
	}

	// Immediate second report should be suppressed by cooldown
	sent2, err := client.Report(context.Background(), ip, "duplicate")
	if err != nil || sent2 {
		t.Fatalf("expected second report to be suppressed, sent=%v err=%v", sent2, err)
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 report HTTP call, got %d", hits.Load())
	}
}

func TestConcurrentAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":50,"totalReports":5}}`))
	}))
	defer srv.Close()

	client := NewClient("key", 90, 2*time.Second, 1*time.Hour, srv.Client())
	client.SetBaseURL(srv.URL)

	ip := netip.MustParseAddr("203.0.113.99")
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.Check(context.Background(), ip)
		}()
	}
	wg.Wait()
}
