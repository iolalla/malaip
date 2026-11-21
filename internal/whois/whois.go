package whois

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Info contains parsed whois attributes for an IP address.
type Info struct {
	IP      netip.Addr
	Country string
	Org     string
	ASN     string
	CIDR    string
}

// DisplayOrg returns a formatted string combining Org and ASN if available.
func (i *Info) DisplayOrg() string {
	org := strings.TrimSpace(i.Org)
	asn := strings.TrimSpace(i.ASN)

	if org == "" && asn == "" {
		return "Desconocida"
	}
	if org != "" && asn != "" {
		if !strings.HasPrefix(strings.ToUpper(asn), "AS") && !strings.Contains(asn, "/") {
			asn = "AS" + asn
		}
		return fmt.Sprintf("%s (%s)", org, asn)
	}
	if org != "" {
		return org
	}
	if !strings.HasPrefix(strings.ToUpper(asn), "AS") && !strings.Contains(asn, "/") {
		asn = "AS" + asn
	}
	return asn
}

type cacheEntry struct {
	info      *Info
	expiresAt time.Time
}

// QueryFunc defines a function signature for executing WHOIS queries.
type QueryFunc func(ctx context.Context, ip string) (string, error)

// Client handles querying whois and caching results with TTL.
type Client struct {
	mu       sync.RWMutex
	cache    map[netip.Addr]*cacheEntry
	timeout  time.Duration
	ttl      time.Duration
	queryFn  QueryFunc
}

// DefaultQuery executes the system `whois` command with the provided IP without using a shell.
func DefaultQuery(ctx context.Context, ip string) (string, error) {
	cmd := exec.CommandContext(ctx, "whois", ip)
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("whois command failed: %w", err)
	}
	return string(out), nil
}

// NewClient initializes a WHOIS client.
func NewClient(timeout, ttl time.Duration, customQuery QueryFunc) *Client {
	if customQuery == nil {
		customQuery = DefaultQuery
	}
	return &Client{
		cache:   make(map[netip.Addr]*cacheEntry),
		timeout: timeout,
		ttl:     ttl,
		queryFn: customQuery,
	}
}

// ParseWhoisOutput extracts Country, Org, ASN, and CIDR from raw whois text.
func ParseWhoisOutput(ip netip.Addr, raw string) *Info {
	info := &Info{IP: ip}

	var orgName, descr, owner string
	var originAS, origin, route, cidr string
	var country string

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}

		switch key {
		case "country":
			if country == "" {
				country = strings.ToUpper(val)
			}
		case "orgname", "org-name":
			if orgName == "" {
				orgName = val
			}
		case "owner":
			if owner == "" {
				owner = val
			}
		case "descr":
			if descr == "" {
				descr = val
			}
		case "originas":
			if originAS == "" {
				originAS = val
			}
		case "origin":
			if origin == "" {
				origin = val
			}
		case "route", "route6":
			if route == "" {
				route = val
			}
		case "cidr":
			if cidr == "" {
				cidr = val
			}
		}
	}

	// Select best organization
	if orgName != "" {
		info.Org = orgName
	} else if owner != "" {
		info.Org = owner
	} else if descr != "" {
		info.Org = descr
	}

	// Country
	info.Country = country

	// ASN / Route / CIDR
	if originAS != "" {
		info.ASN = originAS
	} else if origin != "" {
		info.ASN = origin
	}

	if cidr != "" {
		info.CIDR = cidr
	} else if route != "" {
		info.CIDR = route
	}

	if info.ASN == "" && info.CIDR != "" {
		info.ASN = info.CIDR
	}

	return info
}

// Lookup queries whois for an IP or returns a cached result.
func (c *Client) Lookup(parentCtx context.Context, ip netip.Addr) (*Info, error) {
	ip = ip.Unmap()

	// 1. Check cache with read lock
	c.mu.RLock()
	entry, found := c.cache[ip]
	if found && time.Now().Before(entry.expiresAt) {
		info := entry.info
		c.mu.RUnlock()
		return info, nil
	}
	c.mu.RUnlock()

	// 2. Perform whois query with timeout
	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()

	raw, err := c.queryFn(ctx, ip.String())
	var info *Info
	if err != nil && len(raw) == 0 {
		// Provide basic fallback info if network failed
		info = &Info{
			IP:      ip,
			Country: "??",
			Org:     "Desconocida",
		}
	} else {
		info = ParseWhoisOutput(ip, raw)
	}

	// 3. Store in cache
	c.mu.Lock()
	c.cache[ip] = &cacheEntry{
		info:      info,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return info, err
}

// Cleanup purges expired cache entries.
func (c *Client) Cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for ip, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, ip)
		}
	}
}

// StartAutoCleanup starts a periodic cleanup worker until ctx is cancelled.
func (c *Client) StartAutoCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Cleanup()
			}
		}
	}()
}
