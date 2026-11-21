package whois

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestParseWhoisOutput(t *testing.T) {
	arinSample := `
# ARIN WHOIS data
NetRange:       203.0.113.0 - 203.0.113.255
CIDR:           203.0.113.0/24
OriginAS:       AS12345
OrgName:        Example Corporation
Country:        US
`
	ip := netip.MustParseAddr("203.0.113.50")
	info := ParseWhoisOutput(ip, arinSample)

	if info.Country != "US" {
		t.Errorf("expected Country US, got %q", info.Country)
	}
	if info.Org != "Example Corporation" {
		t.Errorf("expected Org 'Example Corporation', got %q", info.Org)
	}
	if info.ASN != "AS12345" {
		t.Errorf("expected ASN AS12345, got %q", info.ASN)
	}
	if info.CIDR != "203.0.113.0/24" {
		t.Errorf("expected CIDR 203.0.113.0/24, got %q", info.CIDR)
	}
	if info.DisplayOrg() != "Example Corporation (AS12345)" {
		t.Errorf("expected DisplayOrg 'Example Corporation (AS12345)', got %q", info.DisplayOrg())
	}

	apnicSample := `
% APNIC WHOIS data
route:          202.96.0.0/18
descr:          China Telecom Guangdong
origin:         4134
country:        cn
`
	ip2 := netip.MustParseAddr("202.96.0.1")
	info2 := ParseWhoisOutput(ip2, apnicSample)

	if info2.Country != "CN" {
		t.Errorf("expected Country CN, got %q", info2.Country)
	}
	if info2.Org != "China Telecom Guangdong" {
		t.Errorf("expected Org 'China Telecom Guangdong', got %q", info2.Org)
	}
	if info2.DisplayOrg() != "China Telecom Guangdong (AS4134)" {
		t.Errorf("expected DisplayOrg 'China Telecom Guangdong (AS4134)', got %q", info2.DisplayOrg())
	}
}

func TestClientCacheAndTimeout(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	mockQuery := func(ctx context.Context, ip string) (string, error) {
		mu.Lock()
		callCount++
		mu.Unlock()
		return "OrgName: Mock Corp\nCountry: ES\nOriginAS: AS9999\n", nil
	}

	client := NewClient(1*time.Second, 100*time.Millisecond, mockQuery)
	ip := netip.MustParseAddr("198.51.100.1")

	// First query: cache miss -> calls mockQuery
	info, err := client.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Country != "ES" || info.Org != "Mock Corp" {
		t.Fatalf("unexpected info parsed: %+v", info)
	}

	// Second query immediately: cache hit -> does NOT call mockQuery
	info2, err := client.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info2 != info {
		t.Errorf("expected cached pointer")
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("expected callCount=1 on cache hit, got %d", callCount)
	}
	mu.Unlock()

	// Wait for TTL to expire
	time.Sleep(120 * time.Millisecond)

	// Third query: cache expired -> calls mockQuery again
	_, err = client.Lookup(context.Background(), ip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	if callCount != 2 {
		t.Errorf("expected callCount=2 after TTL expired, got %d", callCount)
	}
	mu.Unlock()
}

func TestClientFallbackOnError(t *testing.T) {
	mockFailingQuery := func(ctx context.Context, ip string) (string, error) {
		return "", errors.New("network unreachable")
	}

	client := NewClient(500*time.Millisecond, 1*time.Hour, mockFailingQuery)
	ip := netip.MustParseAddr("203.0.113.9")

	info, err := client.Lookup(context.Background(), ip)
	if err == nil {
		t.Errorf("expected error from failing query")
	}
	if info == nil {
		t.Fatalf("expected fallback info object even on error")
	}
	if info.Org != "Desconocida" {
		t.Errorf("expected Org 'Desconocida', got %q", info.Org)
	}
}

func TestClientConcurrency(t *testing.T) {
	mockQuery := func(ctx context.Context, ip string) (string, error) {
		return "OrgName: Concurrent Corp\nCountry: FR\n", nil
	}

	client := NewClient(1*time.Second, 1*time.Hour, mockQuery)
	ip := netip.MustParseAddr("192.0.2.100")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.Lookup(context.Background(), ip)
		}()
	}
	wg.Wait()

	client.Cleanup()
}
