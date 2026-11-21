package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL is the official AbuseIPDB API v2 base URL.
	DefaultBaseURL = "https://api.abuseipdb.com/api/v2"

	// DefaultReportCooldown matches AbuseIPDB's 15-minute minimum interval between reports for the same IP.
	DefaultReportCooldown = 15 * time.Minute

	// sshReportCategories combines AbuseIPDB categories 18 (Brute-Force) and 22 (SSH).
	sshReportCategories = "18,22"

	// maxCommentLen is AbuseIPDB's maximum accepted comment length in bytes.
	maxCommentLen = 1024
)

// CheckResult holds relevant reputation fields returned by AbuseIPDB's /check endpoint.
type CheckResult struct {
	IP                   netip.Addr
	AbuseConfidenceScore int
	CountryCode          string
	ISP                  string
	UsageType            string
	Domain               string
	TotalReports         int
	IsTor                bool
	IsWhitelisted        bool
}

// FormatSummary returns a concise human-readable summary for desktop notifications.
func (r *CheckResult) FormatSummary() string {
	if r == nil {
		return ""
	}
	reportLabel := "reportes"
	if r.TotalReports == 1 {
		reportLabel = "reporte"
	}
	summary := fmt.Sprintf("%d%% confianza (%d %s)", r.AbuseConfidenceScore, r.TotalReports, reportLabel)
	if r.IsTor {
		summary += " [Tor]"
	}
	return summary
}

type cacheEntry struct {
	result    *CheckResult
	expiresAt time.Time
}

type checkAPIResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		IsTor                bool   `json:"isTor"`
		IsWhitelisted        *bool  `json:"isWhitelisted"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

// Client interacts with the AbuseIPDB v2 API with in-memory TTL caching and report cooldown.
type Client struct {
	mu             sync.RWMutex
	cache          map[netip.Addr]*cacheEntry
	lastReported   map[netip.Addr]time.Time
	httpClient     *http.Client
	baseURL        string
	apiKey         string
	maxAgeInDays   int
	timeout        time.Duration
	ttl            time.Duration
	reportCooldown time.Duration
}

// NewClient initializes an AbuseIPDB API v2 client.
func NewClient(apiKey string, maxAgeInDays int, timeout, ttl time.Duration, httpClient *http.Client) *Client {
	if maxAgeInDays < 1 || maxAgeInDays > 365 {
		maxAgeInDays = 90
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	return &Client{
		cache:          make(map[netip.Addr]*cacheEntry),
		lastReported:   make(map[netip.Addr]time.Time),
		httpClient:     httpClient,
		baseURL:        DefaultBaseURL,
		apiKey:         strings.TrimSpace(apiKey),
		maxAgeInDays:   maxAgeInDays,
		timeout:        timeout,
		ttl:            ttl,
		reportCooldown: DefaultReportCooldown,
	}
}

// SetBaseURL overrides the API base URL (intended for testing).
func (c *Client) SetBaseURL(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = strings.TrimRight(u, "/")
}

// SetReportCooldown overrides the minimum interval between reports for the same IP.
func (c *Client) SetReportCooldown(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reportCooldown = d
}

// Check queries AbuseIPDB for the IP's reputation, returning a cached result if still valid.
func (c *Client) Check(parentCtx context.Context, ip netip.Addr) (*CheckResult, error) {
	ip = ip.Unmap()

	// 1. Check cache under read lock
	c.mu.RLock()
	if entry, found := c.cache[ip]; found && time.Now().Before(entry.expiresAt) {
		res := entry.result
		c.mu.RUnlock()
		return res, nil
	}
	baseURL := c.baseURL
	apiKey := c.apiKey
	maxAge := c.maxAgeInDays
	c.mu.RUnlock()

	if apiKey == "" {
		return nil, fmt.Errorf("abuseipdb API key is empty")
	}

	// 2. Build GET /check request with URL-encoded query params (safe for IPv6)
	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()

	params := url.Values{}
	params.Set("ipAddress", ip.String())
	params.Set("maxAgeInDays", strconv.Itoa(maxAge))

	reqURL := fmt.Sprintf("%s/check?%s", baseURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build abuseipdb check request: %w", err)
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb check request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read abuseipdb response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("abuseipdb rate limit exceeded (HTTP 429)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("abuseipdb check returned HTTP %d", resp.StatusCode)
	}

	var apiResp checkAPIResponse
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode abuseipdb response: %w", err)
	}

	whitelisted := false
	if apiResp.Data.IsWhitelisted != nil {
		whitelisted = *apiResp.Data.IsWhitelisted
	}

	result := &CheckResult{
		IP:                   ip,
		AbuseConfidenceScore: apiResp.Data.AbuseConfidenceScore,
		CountryCode:          strings.ToUpper(strings.TrimSpace(apiResp.Data.CountryCode)),
		ISP:                  strings.TrimSpace(apiResp.Data.ISP),
		UsageType:            strings.TrimSpace(apiResp.Data.UsageType),
		Domain:               strings.TrimSpace(apiResp.Data.Domain),
		TotalReports:         apiResp.Data.TotalReports,
		IsTor:                apiResp.Data.IsTor,
		IsWhitelisted:        whitelisted,
	}

	// 3. Store successful result in cache
	c.mu.Lock()
	c.cache[ip] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return result, nil
}

// Report submits an abusive IP to AbuseIPDB under categories 18 (Brute-Force) and 22 (SSH).
// It enforces a per-IP cooldown (default 15 minutes) to comply with AbuseIPDB API rules.
// Returns (true, nil) if a report was sent, or (false, nil) if suppressed by cooldown.
func (c *Client) Report(parentCtx context.Context, ip netip.Addr, comment string) (bool, error) {
	ip = ip.Unmap()

	c.mu.RLock()
	last, seen := c.lastReported[ip]
	cooldown := c.reportCooldown
	baseURL := c.baseURL
	apiKey := c.apiKey
	c.mu.RUnlock()

	if seen && time.Since(last) < cooldown {
		return false, nil
	}
	if apiKey == "" {
		return false, fmt.Errorf("abuseipdb API key is empty")
	}

	comment = strings.TrimSpace(comment)
	if len(comment) > maxCommentLen {
		comment = comment[:maxCommentLen]
	}

	form := url.Values{}
	form.Set("ip", ip.String())
	form.Set("categories", sshReportCategories)
	if comment != "" {
		form.Set("comment", comment)
	}

	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()

	reqURL := fmt.Sprintf("%s/report", baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("failed to build abuseipdb report request: %w", err)
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("abuseipdb report request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, fmt.Errorf("abuseipdb report rate limit exceeded (HTTP 429)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("abuseipdb report returned HTTP %d", resp.StatusCode)
	}

	c.mu.Lock()
	c.lastReported[ip] = time.Now()
	c.mu.Unlock()

	return true, nil
}

// Cleanup purges expired cache entries and stale report cooldown records.
func (c *Client) Cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for ip, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, ip)
		}
	}
	for ip, reportedAt := range c.lastReported {
		if now.Sub(reportedAt) > c.reportCooldown {
			delete(c.lastReported, ip)
		}
	}
}

// StartAutoCleanup runs periodic cache cleanup until ctx is cancelled.
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
