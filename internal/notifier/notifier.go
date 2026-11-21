package notifier

import (
	"context"
	"fmt"
	"html"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

// Alert encapsulates the fields displayed in a desktop notification.
type Alert struct {
	IP           string
	Country      string
	User         string
	Org          string
	AbuseSummary string
	Attempts     int
}

// Notifier defines the interface for emitting desktop notifications.
type Notifier interface {
	Notify(ctx context.Context, alert Alert) error
	Close() error
}

// DBusNotifier emits notifications via org.freedesktop.Notifications on D-Bus.
type DBusNotifier struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	urgency byte
}

// FormatNotification formats the summary and body with HTML/Pango escaping according to RF-05.
func FormatNotification(a Alert) (summary, body string) {
	summary = "⚠️ Intento fallido de SSH"

	safeIP := html.EscapeString(strings.TrimSpace(a.IP))
	safeCountry := html.EscapeString(strings.TrimSpace(a.Country))
	safeUser := html.EscapeString(strings.TrimSpace(a.User))
	safeOrg := html.EscapeString(strings.TrimSpace(a.Org))
	safeAbuse := html.EscapeString(strings.TrimSpace(a.AbuseSummary))

	var ipLine string
	if safeCountry != "" && safeCountry != "??" {
		ipLine = fmt.Sprintf("IP: %s (%s)", safeIP, safeCountry)
	} else {
		ipLine = fmt.Sprintf("IP: %s", safeIP)
	}

	if safeOrg == "" {
		safeOrg = "Desconocida"
	}

	var lines []string
	lines = append(lines, ipLine)
	lines = append(lines, fmt.Sprintf("Usuario: %s", safeUser))
	lines = append(lines, fmt.Sprintf("Organización: %s", safeOrg))
	if safeAbuse != "" {
		lines = append(lines, fmt.Sprintf("AbuseIPDB: %s", safeAbuse))
	}
	lines = append(lines, fmt.Sprintf("Intentos detectados: %d", a.Attempts))

	body = strings.Join(lines, "\n")

	return summary, body
}

// NewDBusNotifier creates a notifier connected to the user's D-Bus session bus.
func NewDBusNotifier(urgency byte) (*DBusNotifier, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to session D-Bus: %w", err)
	}

	return &DBusNotifier{
		conn:    conn,
		urgency: urgency,
	}, nil
}

// Notify sends a notification via D-Bus, falling back to notify-send if D-Bus fails.
func (n *DBusNotifier) Notify(ctx context.Context, alert Alert) error {
	summary, body := FormatNotification(alert)

	n.mu.Lock()
	conn := n.conn
	n.mu.Unlock()

	if conn != nil {
		obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
		hints := map[string]dbus.Variant{
			"urgency": dbus.MakeVariant(n.urgency),
		}

		// Timeout: 0 indicates the notification never expires automatically (for Critical alerts)
		call := obj.CallWithContext(
			ctx,
			"org.freedesktop.Notifications.Notify",
			0,
			"ssh-watch-gnome",
			uint32(0),
			"dialog-warning",
			summary,
			body,
			[]string{},
			hints,
			int32(0),
		)

		if call.Err == nil {
			return nil
		}
		log.Printf("[notifier] D-Bus call failed: %v; attempting notify-send fallback", call.Err)
	}

	return fallbackNotifySend(ctx, summary, body, n.urgency)
}

// Close closes the D-Bus connection.
func (n *DBusNotifier) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn != nil {
		err := n.conn.Close()
		n.conn = nil
		return err
	}
	return nil
}

// fallbackNotifySend uses notify-send when direct D-Bus communication is unavailable.
func fallbackNotifySend(ctx context.Context, summary, body string, urgency byte) error {
	notifySendPath, err := exec.LookPath("notify-send")
	if err != nil {
		return fmt.Errorf("fallback notify-send binary not found in PATH: %w", err)
	}

	urgencyStr := "critical"
	switch urgency {
	case 0:
		urgencyStr = "low"
	case 1:
		urgencyStr = "normal"
	case 2:
		urgencyStr = "critical"
	default:
		urgencyStr = strconv.Itoa(int(urgency))
	}

	cmd := exec.CommandContext(ctx, notifySendPath,
		"-u", urgencyStr,
		"-i", "dialog-warning",
		"-a", "ssh-watch-gnome",
		summary,
		body,
	)

	return cmd.Run()
}
