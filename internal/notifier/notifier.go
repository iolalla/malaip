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

// Notifier defines the interface for emitting desktop notifications.
type Notifier interface {
	Notify(ctx context.Context, ip, country, user, org string, attempts int) error
	Close() error
}

// DBusNotifier emits notifications via org.freedesktop.Notifications on D-Bus.
type DBusNotifier struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	urgency byte
}

// FormatNotification formats the summary and body with HTML/Pango escaping according to RF-05.
func FormatNotification(ip, country, user, org string, attempts int) (summary, body string) {
	summary = "⚠️ Intento fallido de SSH"

	safeIP := html.EscapeString(strings.TrimSpace(ip))
	safeCountry := html.EscapeString(strings.TrimSpace(country))
	safeUser := html.EscapeString(strings.TrimSpace(user))
	safeOrg := html.EscapeString(strings.TrimSpace(org))

	var ipLine string
	if safeCountry != "" && safeCountry != "??" {
		ipLine = fmt.Sprintf("IP: %s (%s)", safeIP, safeCountry)
	} else {
		ipLine = fmt.Sprintf("IP: %s", safeIP)
	}

	if safeOrg == "" {
		safeOrg = "Desconocida"
	}

	body = fmt.Sprintf("%s\nUsuario: %s\nOrganización: %s\nIntentos detectados: %d",
		ipLine, safeUser, safeOrg, attempts)

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
func (n *DBusNotifier) Notify(ctx context.Context, ip, country, user, org string, attempts int) error {
	summary, body := FormatNotification(ip, country, user, org, attempts)

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
