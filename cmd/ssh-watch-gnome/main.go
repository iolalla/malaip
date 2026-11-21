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
	log.Printf("Configuration loaded: Cooldown=%v, WhoisTTL=%v, WhoisTimeout=%v, WhitelistPrefixes=%d",
		cfg.Cooldown(), cfg.WhoisCacheTTL(), cfg.WhoisTimeout(), len(cfg.WhitelistCIDRs))

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
			if err := notif.Notify(ctx, "203.0.113.45", "CN", "root", "China Telecom (AS4134)", 1); err != nil {
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

			// Asynchronous WHOIS lookup and Notification
			alertWg.Add(1)
			go func(event logwatcher.SSHEvent, totalAttempts int) {
				defer alertWg.Done()

				asyncCtx, asyncCancel := context.WithTimeout(context.Background(), cfg.WhoisTimeout()+3*time.Second)
				defer asyncCancel()

				info, err := whoisClient.Lookup(asyncCtx, event.IP)
				if err != nil {
					log.Printf("WHOIS query warning for %s: %v", event.IP, err)
				}

				country := ""
				org := "Desconocida"
				if info != nil {
					country = info.Country
					org = info.DisplayOrg()
				}

				log.Printf("INTRUSION DETECTED: IP=%s (%s), User=%s, Org=%s, Attempts=%d",
					event.IP, country, event.User, org, totalAttempts)

				if notif != nil {
					if err := notif.Notify(asyncCtx, event.IP.String(), country, event.User, org, totalAttempts); err != nil {
						log.Printf("Error sending notification for %s: %v", event.IP, err)
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
