package limiter

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestLimiterCooldownAndCount(t *testing.T) {
	cooldown := 50 * time.Millisecond
	lim := New(cooldown)
	ip := netip.MustParseAddr("203.0.113.10")

	// 1st attempt: should notify
	notify, attempts := lim.Record(ip)
	if !notify {
		t.Fatalf("expected 1st attempt to notify")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts)
	}

	// Immediate 2nd through 50th attempts: should NOT notify
	for i := 2; i <= 50; i++ {
		notify, attempts = lim.Record(ip)
		if notify {
			t.Fatalf("expected attempt %d to be suppressed by cooldown", i)
		}
		if attempts != i {
			t.Fatalf("expected %d attempts, got %d", i, attempts)
		}
	}

	// Sleep longer than cooldown
	time.Sleep(60 * time.Millisecond)

	// 51st attempt: should notify again after cooldown
	notify, attempts = lim.Record(ip)
	if !notify {
		t.Fatalf("expected attempt after cooldown to notify")
	}
	if attempts != 51 {
		t.Fatalf("expected 51 attempts, got %d", attempts)
	}
}

func TestLimiterConcurrency(t *testing.T) {
	lim := New(1 * time.Second)
	ip := netip.MustParseAddr("198.51.100.5")

	var wg sync.WaitGroup
	numWorkers := 20
	iterationsPerWorker := 50

	notifyCount := 0
	var mu sync.Mutex

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterationsPerWorker; i++ {
				notify, _ := lim.Record(ip)
				if notify {
					mu.Lock()
					notifyCount++
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	totalExpected := numWorkers * iterationsPerWorker
	if lim.GetAttempts(ip) != totalExpected {
		t.Errorf("expected %d attempts, got %d", totalExpected, lim.GetAttempts(ip))
	}

	if notifyCount != 1 {
		t.Errorf("expected exactly 1 notification during initial burst, got %d", notifyCount)
	}
}

func TestLimiterCleanup(t *testing.T) {
	lim := New(10 * time.Millisecond)
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")

	lim.Record(ip1)
	time.Sleep(20 * time.Millisecond)
	lim.Record(ip2)

	// Clean up entries older than 15ms -> ip1 should be removed, ip2 should stay
	lim.Cleanup(15 * time.Millisecond)

	if lim.GetAttempts(ip1) != 0 {
		t.Errorf("expected ip1 to be cleaned up")
	}
	if lim.GetAttempts(ip2) != 1 {
		t.Errorf("expected ip2 to remain")
	}

	// Test StartAutoCleanup with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	lim.StartAutoCleanup(ctx, 10*time.Millisecond, 10*time.Millisecond)
	cancel()
}
