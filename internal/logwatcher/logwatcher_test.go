package logwatcher

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		shouldMatch bool
		expectedIP  string
		expectedUser string
	}{
		{
			name:        "Failed password with invalid user (IPv4)",
			line:        "Failed password for invalid user admin from 203.0.113.45 port 42312 ssh2",
			shouldMatch: true,
			expectedIP:  "203.0.113.45",
			expectedUser: "admin",
		},
		{
			name:        "Failed password for valid user (IPv4)",
			line:        "Failed password for root from 198.51.100.12 port 54321 ssh2",
			shouldMatch: true,
			expectedIP:  "198.51.100.12",
			expectedUser: "root",
		},
		{
			name:        "Failed password for user (IPv6)",
			line:        "Failed password for invalid user guest from 2001:db8:85a3::8a2e:370:7334 port 2222 ssh2",
			shouldMatch: true,
			expectedIP:  "2001:db8:85a3::8a2e:370:7334",
			expectedUser: "guest",
		},
		{
			name:        "Invalid user (IPv4)",
			line:        "Invalid user testuser from 192.0.2.15 port 39821",
			shouldMatch: true,
			expectedIP:  "192.0.2.15",
			expectedUser: "testuser",
		},
		{
			name:        "Invalid user (IPv6)",
			line:        "Invalid user scanner from ::ffff:192.0.2.1 port 55123",
			shouldMatch: true,
			expectedIP:  "192.0.2.1", // unmapped from ::ffff:192.0.2.1
			expectedUser: "scanner",
		},
		{
			name:        "Connection closed by authenticating user preauth (IPv4)",
			line:        "Connection closed by authenticating user ubuntu 203.0.113.88 port 60124 [preauth]",
			shouldMatch: true,
			expectedIP:  "203.0.113.88",
			expectedUser: "ubuntu",
		},
		{
			name:        "Maximum authentication attempts exceeded (IPv4)",
			line:        "error: maximum authentication attempts exceeded for root from 198.51.100.99 port 41234 ssh2 [preauth]",
			shouldMatch: true,
			expectedIP:  "198.51.100.99",
			expectedUser: "root",
		},
		{
			name:        "Maximum authentication attempts exceeded without port (IPv6)",
			line:        "error: maximum authentication attempts exceeded for invalid user test from 2001:db8::1",
			shouldMatch: true,
			expectedIP:  "2001:db8::1",
			expectedUser: "test",
		},
		{
			name:        "Accepted password should NOT match",
			line:        "Accepted password for root from 192.168.1.50 port 22 ssh2",
			shouldMatch: false,
		},
		{
			name:        "Accepted publickey should NOT match",
			line:        "Accepted publickey for user1 from 192.168.1.60 port 22 ssh2: RSA SHA256:...",
			shouldMatch: false,
		},
		{
			name:        "Malformed IP address in failed password line",
			line:        "Failed password for root from 999.999.999.999 port 22 ssh2",
			shouldMatch: false,
		},
		{
			name:        "Completely unrelated log line",
			line:        "pam_unix(sshd:session): session opened for user test by (uid=0)",
			shouldMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := ParseLine(tc.line)
			if ok != tc.shouldMatch {
				t.Fatalf("expected match=%v, got %v for line %q", tc.shouldMatch, ok, tc.line)
			}
			if tc.shouldMatch {
				if ev == nil {
					t.Fatalf("expected non-nil event")
				}
				expectedAddr := netip.MustParseAddr(tc.expectedIP).Unmap()
				if ev.IP != expectedAddr {
					t.Errorf("expected IP %s, got %s", expectedAddr, ev.IP)
				}
				if ev.User != tc.expectedUser {
					t.Errorf("expected User %q, got %q", tc.expectedUser, ev.User)
				}
			}
		})
	}
}

func TestStreamReader(t *testing.T) {
	logContent := `
pam_unix(sshd:auth): check pass; user unknown
Failed password for invalid user hacker from 203.0.113.111 port 12345 ssh2
Accepted publickey for admin from 10.0.0.1 port 22 ssh2
Invalid user badguy from 203.0.113.222 port 54321
`
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eventsChan := make(chan SSHEvent, 10)
	r := strings.NewReader(logContent)

	err := StreamReader(ctx, r, eventsChan)
	if err != nil {
		t.Fatalf("StreamReader failed: %v", err)
	}

	close(eventsChan)

	var collected []SSHEvent
	for ev := range eventsChan {
		collected = append(collected, ev)
	}

	if len(collected) != 2 {
		t.Fatalf("expected 2 events, got %d", len(collected))
	}

	if collected[0].User != "hacker" || collected[0].IP.String() != "203.0.113.111" {
		t.Errorf("unexpected event 0: %+v", collected[0])
	}
	if collected[1].User != "badguy" || collected[1].IP.String() != "203.0.113.222" {
		t.Errorf("unexpected event 1: %+v", collected[1])
	}
}
