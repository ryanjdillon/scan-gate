// Command secretscan serves Betterleaks secret detection over a Unix domain
// socket: POST /scan returns code point spans and rule ids, never a matched
// value. It listens on no TCP port and makes no outbound connection.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

const (
	defaultSocket = "/run/secretscan/sock"
	// At the detector's roughly 5-7 MB/s, 8 MiB is about the most that
	// finishes inside the default deadline; a larger body would only burn
	// CPU on its way to a 504.
	defaultMaxBytes = 8 << 20
	defaultTimeout  = 2 * time.Second
)

// errNoEgress is what any outbound HTTP request in this process gets.
var errNoEgress = errors.New("secretscan: outbound HTTP is disabled")

type refuseTransport struct{}

func (refuseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errNoEgress
}

// denyOutboundHTTP replaces the process-wide default transport. Betterleaks'
// expression runtime has HTTP bindings for secret validation, built on clients
// with no transport of their own, so they fall through to this one. Validation
// is off, so they are never called; this makes sure a ruleset change cannot
// turn them on. The pod's deny-all egress NetworkPolicy is the outer boundary.
func denyOutboundHTTP() {
	http.DefaultTransport = refuseTransport{}
	http.DefaultClient = &http.Client{Transport: refuseTransport{}}
}

type settings struct {
	socket   string
	maxBytes int64
	timeout  time.Duration
}

func loadSettings(getenv func(string) string) (settings, error) {
	s := settings{socket: defaultSocket, maxBytes: defaultMaxBytes, timeout: defaultTimeout}
	if v := getenv("SECRETSCAN_SOCKET"); v != "" {
		s.socket = v
	}
	if v := getenv("SECRETSCAN_MAX_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return s, fmt.Errorf("SECRETSCAN_MAX_BYTES must be a positive integer, got %q", v)
		}
		s.maxBytes = n
	}
	if v := getenv("SECRETSCAN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return s, fmt.Errorf("SECRETSCAN_TIMEOUT must be a positive duration, got %q", v)
		}
		s.timeout = d
	}
	return s, nil
}

// listenUnix listens on path with mode 0600, replacing a stale socket left by
// an earlier run. The umask covers the window between bind and chmod.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("secretscan stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	denyOutboundHTTP()
	cfg, err := loadSettings(os.Getenv)
	if err != nil {
		return err
	}
	began := time.Now()
	scanner, err := NewScanner()
	if err != nil {
		return err
	}
	logger.Info("detector ready", "rules", scanner.RuleCount(), "duration_ms", time.Since(began).Milliseconds())

	ln, err := listenUnix(cfg.socket)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           NewServer(scanner, cfg.maxBytes, cfg.timeout, runtime.GOMAXPROCS(0), logger).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.timeout + 30*time.Second,
		IdleTimeout:       2 * time.Minute,
		// net/http logs a recovered handler panic with its value, which
		// could quote request text, so its own messages are dropped.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	logger.Info("listening", "socket", cfg.socket, "max_bytes", cfg.maxBytes, "timeout", cfg.timeout.String())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), cfg.timeout+time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
