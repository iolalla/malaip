package logwatcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// SSHEvent represents a detected SSH intrusion or failed authentication attempt.
type SSHEvent struct {
	IP        netip.Addr
	User      string
	Timestamp time.Time
	Raw       string
}

type patternEntry struct {
	regex     *regexp.Regexp
	userIndex int
	ipIndex   int
}

var (
	compiledPatterns = []patternEntry{}

	rawRegexStrings = []string{
		`Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+`,
		`Invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+`,
		`Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port \d+ \[preauth\]`,
		`error: maximum authentication attempts exceeded for (?:(?:invalid user )?(?P<user>\S+)|.*?) from (?P<ip>\S+)`,
	}
)

func init() {
	for _, raw := range rawRegexStrings {
		re := regexp.MustCompile(raw)
		uIdx := re.SubexpIndex("user")
		ipIdx := re.SubexpIndex("ip")
		compiledPatterns = append(compiledPatterns, patternEntry{
			regex:     re,
			userIndex: uIdx,
			ipIndex:   ipIdx,
		})
	}
}

// ParseLine parses a single log line against sshd failure patterns.
// If an intrusion pattern matches and contains a valid IP address, it returns an SSHEvent.
func ParseLine(line string) (*SSHEvent, bool) {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return nil, false
	}

	for _, entry := range compiledPatterns {
		matches := entry.regex.FindStringSubmatch(cleanLine)
		if len(matches) == 0 {
			continue
		}

		var ipStr string
		if entry.ipIndex >= 0 && entry.ipIndex < len(matches) {
			ipStr = matches[entry.ipIndex]
		}
		if ipStr == "" {
			continue
		}

		// Validate IP strictly with net/netip
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}

		user := "unknown"
		if entry.userIndex >= 0 && entry.userIndex < len(matches) && matches[entry.userIndex] != "" {
			user = matches[entry.userIndex]
		}

		return &SSHEvent{
			IP:        addr.Unmap(),
			User:      user,
			Timestamp: time.Now(),
			Raw:       cleanLine,
		}, true
	}

	return nil, false
}

// StreamReader reads lines from r and sends parsed SSHEvents to eventsChan until r reaches EOF or ctx is done.
func StreamReader(ctx context.Context, r io.Reader, eventsChan chan<- SSHEvent) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		event, matched := ParseLine(line)
		if !matched {
			continue
		}

		select {
		case eventsChan <- *event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// WatchJournal runs journalctl capturing sshd events via units and syslog identifier,
// feeding parsed events into eventsChan.
func WatchJournal(ctx context.Context, eventsChan chan<- SSHEvent) error {
	// Match both systemd units (ssh.service, sshd.service) and syslog identifier (sshd)
	// so that real sshd instances, socket-activated connections (ssh@...), and tests (logger -t sshd)
	// are all reliably captured in real time without invoking a shell (/bin/sh -c).
	cmd := exec.CommandContext(ctx, "journalctl",
		"_SYSTEMD_UNIT=ssh.service", "+",
		"_SYSTEMD_UNIT=sshd.service", "+",
		"SYSLOG_IDENTIFIER=sshd",
		"-f", "-n", "0", "-o", "cat",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe for journalctl: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe for journalctl: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start journalctl: %w", err)
	}

	// Read stderr in a separate goroutine for diagnostic logging
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("[journalctl stderr] %s", scanner.Text())
		}
	}()

	errStream := StreamReader(ctx, stdout, eventsChan)
	_ = cmd.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errStream
}
