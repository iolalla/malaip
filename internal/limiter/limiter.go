package limiter

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type ipRecord struct {
	attempts     int
	lastSeen     time.Time
	lastNotified time.Time
}

// Limiter manages frequency of notifications and groups attack attempts per IP.
type Limiter struct {
	mu       sync.RWMutex
	cooldown time.Duration
	records  map[netip.Addr]*ipRecord
}

// New creates a new Limiter with the specified cooldown period.
func New(cooldown time.Duration) *Limiter {
	return &Limiter{
		cooldown: cooldown,
		records:  make(map[netip.Addr]*ipRecord),
	}
}

// Record records an event for the given IP address.
// Returns shouldNotify = true if a notification should be fired, along with the total attempt count.
// If the IP is still within its cooldown window, shouldNotify = false.
func (l *Limiter) Record(ip netip.Addr) (shouldNotify bool, attempts int) {
	ip = ip.Unmap()
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	rec, exists := l.records[ip]
	if !exists {
		rec = &ipRecord{
			attempts:     1,
			lastSeen:     now,
			lastNotified: now,
		}
		l.records[ip] = rec
		return true, 1
	}

	rec.attempts++
	rec.lastSeen = now

	if now.Sub(rec.lastNotified) >= l.cooldown {
		rec.lastNotified = now
		return true, rec.attempts
	}

	return false, rec.attempts
}

// GetAttempts returns the number of recorded attempts for an IP.
func (l *Limiter) GetAttempts(ip netip.Addr) int {
	ip = ip.Unmap()
	l.mu.RLock()
	defer l.mu.RUnlock()

	if rec, ok := l.records[ip]; ok {
		return rec.attempts
	}
	return 0
}

// Cleanup removes entries that haven't been seen for longer than maxAge.
func (l *Limiter) Cleanup(maxAge time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	for ip, rec := range l.records {
		if now.Sub(rec.lastSeen) > maxAge {
			delete(l.records, ip)
		}
	}
}

// StartAutoCleanup starts a periodic cleanup worker in a goroutine until ctx is cancelled.
func (l *Limiter) StartAutoCleanup(ctx context.Context, interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.Cleanup(maxAge)
			}
		}
	}()
}
