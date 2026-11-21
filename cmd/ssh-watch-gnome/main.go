package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ssh-watch-gnome/internal/abuseipdb"
	"ssh-watch-gnome/internal/config"
	"ssh-watch-gnome/internal/limiter"
	"ssh-watch-gnome/internal/logwatcher"
	"ssh-watch-gnome/internal/notifier"
	"ssh-watch-gnome/internal/whois"
)

var (
	version = "1.0.0"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	testNotify := flag.Bool("test-notify", false, "Send a test notification and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ssh-watch-gnome version %s\n", version)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[ssh-watch-gnome] ")
	log.Printf("Starting SSH Guard GNOME v%s...", version)

	// 1. Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Fatal configuration error: %v", err)
	}
	log.Printf("Configuration loaded: Cooldown=%v, WhoisTTL=%v, WhoisTimeout=%v, WhitelistPrefixes=%d, AbuseIPDB=%v",
		cfg.Cooldown(), cfg.WhoisCacheTTL(), cfg.WhoisTimeout(), len(cfg.WhitelistCIDRs), cfg.AbuseIPDB.IsActive())

	// 2. Initialize notifier
	notif, err := notifier.NewDBusNotifier(cfg.Urgency)
	if err != nil {
		log.Printf("Warning: direct D-Bus session unavailable (%v). Notifier will use fallback.", err)
	} else {
		defer notif.Close()
	}

	// Optional test notification flag
	if *testNotify {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		log.Println("Sending test desktop notification...")
		if notif != nil {
			err := notif.Notify(ctx, notifier.Alert{
				IP:           "203.0.113.45",
				Country:      "CN",
				User:         "root",
				Org:          "China Telecom (AS4134)",
				AbuseSummary: "100% confianza (42 reportes)",
				Attempts:     1,
			})
			if err != nil {
				log.Fatalf("Failed to send test notification: %v", err)
			}
		}
		log.Println("Test notification dispatched successfully.")
		os.Exit(0)
	}

	// 3. Graceful shutdown context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 4. Rate limiter with auto cleanup
	lim := limiter.New(cfg.Cooldown())
	lim.StartAutoCleanup(ctx, 10*time.Minute, 2*time.Hour)

	// 5. WHOIS client with TTL cache & auto cleanup
	whoisClient := whois.NewClient(cfg.WhoisTimeout(), cfg.WhoisCacheTTL(), nil)
	whoisClient.StartAutoCleanup(ctx, 1*time.Hour)

	// 5b. Optional AbuseIPDB client with TTL cache & auto cleanup
	var abuseClient *abuseipdb.Client
	if cfg.AbuseIPDB.IsActive() {
		abuseClient = abuseipdb.NewClient(
			cfg.AbuseIPDB.APIKey,
			cfg.AbuseIPDB.MaxAgeInDays,
			cfg.AbuseIPDB.Timeout(),
			cfg.AbuseIPDB.CacheTTL(),
			nil,
		)
		abuseClient.StartAutoCleanup(ctx, 1*time.Hour)
		log.Printf("AbuseIPDB integration enabled (MaxAge=%dd, CacheTTL=%v, AutoReport=%v)",
			cfg.AbuseIPDB.MaxAgeInDays, cfg.AbuseIPDB.CacheTTL(), cfg.AbuseIPDB.ReportEnabled)
	} else if cfg.AbuseIPDB.Enabled {
		log.Println("Warning: AbuseIPDB is enabled in config, but no API key was provided (config or ABUSEIPDB_API_KEY).")
	}

	// 6. Channel for log events
	eventsChan := make(chan logwatcher.SSHEvent, 128)

	// 7. Start log streaming in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			log.Println("Connecting to journalctl stream for sshd...")
			err := logwatcher.WatchJournal(ctx, eventsChan)
			if err != nil && ctx.Err() == nil {
				log.Printf("journalctl stream closed with error: %v. Reconnecting in 3s...", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(3 * time.Second):
				}
			}
		}
	}()

	// 8. Event processing loop
	log.Println("Ready. Monitoring SSH authentication logs...")

	var alertWg sync.WaitGroup

eventLoop:
	for {
		select {
		case <-ctx.Done():
			log.Println("Termination signal received. Initiating graceful shutdown...")
			break eventLoop

		case ev, ok := <-eventsChan:
			if !ok {
				break eventLoop
			}

			// Whitelist check
			if cfg.IsWhitelisted(ev.IP) {
				log.Printf("Ignored: IP %s matches whitelist CIDR", ev.IP)
				continue
			}

			// Cooldown rate-limit check
			shouldNotify, attempts := lim.Record(ev.IP)
			if !shouldNotify {
				log.Printf("Suppressed by cooldown: IP %s (attempt #%d)", ev.IP, attempts)
				continue
			}

			// Asynchronous WHOIS + AbuseIPDB enrichment and Notification
			alertWg.Add(1)
			go func(event logwatcher.SSHEvent, totalAttempts int) {
				defer alertWg.Done()

				enrichTimeout := cfg.WhoisTimeout()
				if abuseClient != nil && cfg.AbuseIPDB.Timeout() > enrichTimeout {
					enrichTimeout = cfg.AbuseIPDB.Timeout()
				}
				asyncCtx, asyncCancel := context.WithTimeout(context.Background(), enrichTimeout+3*time.Second)
				defer asyncCancel()

				var (
					info     *whois.Info
					whoisErr error
					abuseRes *abuseipdb.CheckResult
					abuseErr error
					enrichWg sync.WaitGroup
				)

				enrichWg.Add(1)
				go func() {
					defer enrichWg.Done()
					info, whoisErr = whoisClient.Lookup(asyncCtx, event.IP)
				}()

				if abuseClient != nil {
					enrichWg.Add(1)
					go func() {
						defer enrichWg.Done()
						abuseRes, abuseErr = abuseClient.Check(asyncCtx, event.IP)
					}()
				}

				enrichWg.Wait()

				if whoisErr != nil {
					log.Printf("WHOIS query warning for %s: %v", event.IP, whoisErr)
				}
				if abuseErr != nil {
					log.Printf("AbuseIPDB query warning for %s: %v", event.IP, abuseErr)
				}

				country := ""
				org := "Desconocida"
				if info != nil {
					country = info.Country
					org = info.DisplayOrg()
				}

				abuseSummary := ""
				if abuseRes != nil {
					abuseSummary = abuseRes.FormatSummary()
					if (country == "" || country == "??") && abuseRes.CountryCode != "" {
						country = abuseRes.CountryCode
					}
					if org == "Desconocida" && abuseRes.ISP != "" {
						org = abuseRes.ISP
					}
				}

				if abuseSummary != "" {
					log.Printf("INTRUSION DETECTED: IP=%s (%s), User=%s, Org=%s, AbuseIPDB=[%s], Attempts=%d",
						event.IP, country, event.User, org, abuseSummary, totalAttempts)
				} else {
					log.Printf("INTRUSION DETECTED: IP=%s (%s), User=%s, Org=%s, Attempts=%d",
						event.IP, country, event.User, org, totalAttempts)
				}

				if notif != nil {
					err := notif.Notify(asyncCtx, notifier.Alert{
						IP:           event.IP.String(),
						Country:      country,
						User:         event.User,
						Org:          org,
						AbuseSummary: abuseSummary,
						Attempts:     totalAttempts,
					})
					if err != nil {
						log.Printf("Error sending notification for %s: %v", event.IP, err)
					}
				}

				if abuseClient != nil && cfg.AbuseIPDB.ReportEnabled && totalAttempts >= cfg.AbuseIPDB.ReportMinAttempts {
					comment := fmt.Sprintf("SSH authentication failure for user %s (%d attempts detected by ssh-watch-gnome)", event.User, totalAttempts)
					if sent, err := abuseClient.Report(asyncCtx, event.IP, comment); err != nil {
						log.Printf("AbuseIPDB report warning for %s: %v", event.IP, err)
					} else if sent {
						log.Printf("Reported IP %s to AbuseIPDB (categories 18,22)", event.IP)
					}
				}
			}(ev, attempts)
		}
	}

	// Wait for ongoing notifications with a short timeout
	waitChan := make(chan struct{})
	go func() {
		alertWg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		log.Println("All background tasks completed cleanly.")
	case <-time.After(3 * time.Second):
		log.Println("Timed out waiting for background tasks.")
	}

	log.Println("ssh-watch-gnome stopped.")
}
