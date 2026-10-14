package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// blockingScanner never finishes on its own; it returns when ctx ends.
type blockingScanner struct{}

func (blockingScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// failingScanner always errors, with a message that must not reach a client.
type failingScanner struct{ msg string }

func (f failingScanner) Scan(context.Context, string) ([]Finding, error) {
	return nil, errors.New(f.msg)
}

func scanBody(t testing.TB, text string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(h http.Handler, body []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body)))
	return rec
}

func realHandler(t testing.TB) http.Handler {
	return NewServer(testScanner(t), defaultMaxBytes, defaultTimeout, 4, discardLog()).Handler()
}

func TestScanEndpointReturnsSpansAndNeverValues(t *testing.T) {
	h := realHandler(t)
	pat, key := fakeGitHubPAT(t), fakePrivateKey(t)
	text := "æøå 🎉\r\ntoken " + pat + "\n" + key + "\n"

	rec := post(h, scanBody(t, text))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, secret := range append([]string{pat, key}, strings.Split(key, "\n")[1:3]...) {
		if strings.Contains(body, secret) {
			t.Fatal("response contains a matched value")
		}
	}
	var resp struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Findings) < 2 {
		t.Fatalf("want findings for the token and the key, got %s", body)
	}
	runes := []rune(text)
	for _, f := range resp.Findings {
		if len(f) != 3 {
			t.Fatalf("finding has fields beyond start, end and rule_id: %v", f)
		}
		start, end := int(f["start"].(float64)), int(f["end"].(float64))
		got := string(runes[start:end])
		if got != pat && got != key {
			t.Fatalf("span [%d,%d) for %v does not cover a whole secret", start, end, f["rule_id"])
		}
	}
}

func TestScanEndpointProseIsEmptyList(t *testing.T) {
	rec := post(realHandler(t), scanBody(t, prose))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"findings":[]}` {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestScanEndpointRefusals(t *testing.T) {
	small := NewServer(blockingScanner{}, 64, 50*time.Millisecond, 1, discardLog()).Handler()
	cases := []struct {
		name string
		h    http.Handler
		body []byte
		want int
	}{
		{"over the limit", small, scanBody(t, strings.Repeat("a", 100)), http.StatusRequestEntityTooLarge},
		{"deadline", small, scanBody(t, "short"), http.StatusGatewayTimeout},
		{"not json", small, []byte("text=hello"), http.StatusBadRequest},
		{"no text field", small, []byte(`{"body":"x"}`), http.StatusBadRequest},
		{"text not a string", small, []byte(`{"text":1}`), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := post(tc.h, tc.body); rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// TestScanEndpointDefaultLimit sends one byte over the default limit without
// a Content-Length, so the streaming limit (not the header check) refuses it.
func TestScanEndpointDefaultLimit(t *testing.T) {
	h := NewServer(blockingScanner{}, defaultMaxBytes, time.Second, 1, discardLog()).Handler()
	body := scanBody(t, strings.Repeat("a", defaultMaxBytes))
	req := httptest.NewRequest(http.MethodPost, "/scan", io.MultiReader(bytes.NewReader(body)))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
}

func TestScanEndpointDeadlineWithQueuedScan(t *testing.T) {
	// One slot, held by a scan that never ends: the next request waits for a
	// slot until its own deadline and gets 504.
	h := NewServer(blockingScanner{}, 1024, 50*time.Millisecond, 1, discardLog()).Handler()
	first := make(chan int)
	go func() { first <- post(h, scanBody(t, "a")).Code }()
	if rec := post(h, scanBody(t, "b")); rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("queued request: status %d, want 504", rec.Code)
	}
	if code := <-first; code != http.StatusGatewayTimeout {
		t.Fatalf("first request: status %d, want 504", code)
	}
}

// signalReader reports its first Read, so a test can tell when a handler
// starts consuming the body.
type signalReader struct {
	r    io.Reader
	read chan struct{}
	once sync.Once
}

func (s *signalReader) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.read) })
	return s.r.Read(p)
}

// gatedScanner reports each scan on started, then blocks it until release
// is closed.
type gatedScanner struct{ started, release chan struct{} }

func (g gatedScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	g.started <- struct{}{}
	select {
	case <-g.release:
		return []Finding{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestScanEndpointReadsBodyOnlyWithASlot(t *testing.T) {
	gate := gatedScanner{started: make(chan struct{}, 2), release: make(chan struct{})}
	h := NewServer(gate, 1024, 5*time.Second, 1, discardLog()).Handler()

	first := make(chan int)
	go func() { first <- post(h, scanBody(t, "first")).Code }()
	<-gate.started // the first request now holds the only slot

	body := &signalReader{r: bytes.NewReader(scanBody(t, "second")), read: make(chan struct{})}
	second := make(chan int)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/scan", body))
		second <- rec.Code
	}()

	select {
	case <-body.read:
		t.Fatal("a request read its body while every slot was taken")
	case <-time.After(200 * time.Millisecond):
	}
	close(gate.release)
	select {
	case <-body.read:
	case <-time.After(2 * time.Second):
		t.Fatal("the queued request never read its body after a slot freed")
	}
	if code := <-first; code != http.StatusOK {
		t.Fatalf("first request: status %d", code)
	}
	if code := <-second; code != http.StatusOK {
		t.Fatalf("second request: status %d", code)
	}
}

// panickingScanner panics with a value that must not reach a client or log.
type panickingScanner struct{ value string }

func (p panickingScanner) Scan(context.Context, string) ([]Finding, error) {
	panic(p.value)
}

func TestScanEndpointRecoversPanic(t *testing.T) {
	const leaked = "ghp_panic-value-must-not-be-logged"
	var logs bytes.Buffer
	h := NewServer(panickingScanner{leaked}, 1024, time.Second, 1, slog.New(slog.NewJSONHandler(&logs, nil))).Handler()
	for range 2 { // the second request proves the slot was released
		rec := post(h, scanBody(t, "x"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status %d, want 500", rec.Code)
		}
		if strings.Contains(rec.Body.String(), leaked) {
			t.Fatal("panic value reached the response")
		}
	}
	if strings.Contains(logs.String(), leaked) || !strings.Contains(logs.String(), `"panic_type":"string"`) {
		t.Fatalf("log should name only the panic type: %s", logs.String())
	}
}

func TestScanEndpointErrorHidesMessage(t *testing.T) {
	const leaked = "ghp_this-must-not-be-echoed"
	var logs bytes.Buffer
	h := NewServer(failingScanner{leaked}, 1024, time.Second, 1, slog.New(slog.NewJSONHandler(&logs, nil))).Handler()
	rec := post(h, scanBody(t, "x"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), leaked) || strings.Contains(logs.String(), leaked) {
		t.Fatal("error message reached the response or the log")
	}
}

func TestLogsCarryNoText(t *testing.T) {
	var logs bytes.Buffer
	h := NewServer(testScanner(t), defaultMaxBytes, defaultTimeout, 1, slog.New(slog.NewJSONHandler(&logs, nil))).Handler()
	pat := fakeGitHubPAT(t)
	if rec := post(h, scanBody(t, "marker-text-æøå "+pat)); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	out := logs.String()
	if strings.Contains(out, pat) || strings.Contains(out, "marker-text") {
		t.Fatalf("log carries request text: %s", out)
	}
	if !strings.Contains(out, "github-pat") {
		t.Fatalf("log lacks the rule id: %s", out)
	}
}

func TestHealthzOverUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	if err := os.WriteFile(path, nil, 0o644); err != nil { // a stale file to replace
		t.Fatal(err)
	}
	ln, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want a 0600 socket", info.Mode())
	}
	srv := &http.Server{Handler: NewServer(blockingScanner{}, 1024, time.Second, 1, discardLog()).Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	resp, err := client.Get("http://secretscan/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}
	if resp, err := client.Get("http://secretscan/scan"); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /scan: %v %v", resp, err)
	}
}

func TestDenyOutboundHTTP(t *testing.T) {
	transport, client := http.DefaultTransport, http.DefaultClient
	t.Cleanup(func() { http.DefaultTransport, http.DefaultClient = transport, client })

	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("an outbound request reached the network")
	}))
	defer target.Close()

	denyOutboundHTTP()
	// A client with no transport of its own, as Betterleaks' expression
	// runtime builds, and the package-level helpers.
	for _, get := range []func(string) (*http.Response, error){
		(&http.Client{Timeout: time.Second}).Get,
		http.Get,
	} {
		if _, err := get(target.URL); !errors.Is(err, errNoEgress) {
			t.Fatalf("outbound request error = %v, want errNoEgress", err)
		}
	}
}

func TestLoadSettings(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	got, err := loadSettings(env(nil))
	if err != nil || got != (settings{defaultSocket, defaultMaxBytes, defaultTimeout}) {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	got, err = loadSettings(env(map[string]string{
		"SECRETSCAN_SOCKET": "/tmp/x", "SECRETSCAN_MAX_BYTES": "10", "SECRETSCAN_TIMEOUT": "250ms",
	}))
	if err != nil || got != (settings{"/tmp/x", 10, 250 * time.Millisecond}) {
		t.Fatalf("overrides: %+v %v", got, err)
	}
	for _, bad := range []map[string]string{
		{"SECRETSCAN_MAX_BYTES": "0"},
		{"SECRETSCAN_MAX_BYTES": "lots"},
		{"SECRETSCAN_TIMEOUT": "-1s"},
		{"SECRETSCAN_TIMEOUT": "2"},
	} {
		if _, err := loadSettings(env(bad)); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}
