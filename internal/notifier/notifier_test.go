package notifier

import (
	"strings"
	"testing"
)

func TestFormatNotificationEscaping(t *testing.T) {
	summary, body := FormatNotification(Alert{
		IP:           "203.0.113.45",
		Country:      "CN",
		User:         "<script>alert('xss')</script>&root",
		Org:          "China & Telecom <AS4134>",
		AbuseSummary: "100% confianza (42 reportes) <Tor>",
		Attempts:     3,
	})

	if summary != "⚠️ Intento fallido de SSH" {
		t.Errorf("unexpected summary: %q", summary)
	}

	// Verify no raw '<', '>', or standalone '&' in user, org, or abuse summary
	if strings.Contains(body, "<script>") {
		t.Errorf("body contains unescaped <script>: %s", body)
	}
	if strings.Contains(body, "<AS4134>") {
		t.Errorf("body contains unescaped <AS4134>: %s", body)
	}
	if strings.Contains(body, "<Tor>") {
		t.Errorf("body contains unescaped <Tor>: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped &lt;script&gt; in body: %s", body)
	}
	if !strings.Contains(body, "&amp;root") {
		t.Errorf("expected escaped &amp;root in body: %s", body)
	}
	if !strings.Contains(body, "China &amp; Telecom &lt;AS4134&gt;") {
		t.Errorf("expected escaped org in body: %s", body)
	}
	if !strings.Contains(body, "AbuseIPDB: 100% confianza (42 reportes) &lt;Tor&gt;") {
		t.Errorf("expected escaped AbuseIPDB line in body: %s", body)
	}
	if !strings.Contains(body, "IP: 203.0.113.45 (CN)") {
		t.Errorf("expected IP line with country: %s", body)
	}
	if !strings.Contains(body, "Intentos detectados: 3") {
		t.Errorf("expected attempts line: %s", body)
	}
}

func TestFormatNotificationWithoutCountry(t *testing.T) {
	_, body := FormatNotification(Alert{
		IP:       "198.51.100.1",
		Country:  "",
		User:     "admin",
		Org:      "",
		Attempts: 1,
	})

	if strings.Contains(body, "()") {
		t.Errorf("should not contain empty parens for country: %s", body)
	}
	if !strings.Contains(body, "IP: 198.51.100.1\n") {
		t.Errorf("expected clean IP line without country parens: %s", body)
	}
	if !strings.Contains(body, "Organización: Desconocida") {
		t.Errorf("expected default Organización: Desconocida, got: %s", body)
	}
	if strings.Contains(body, "AbuseIPDB:") {
		t.Errorf("should omit AbuseIPDB line when summary is empty: %s", body)
	}
}
