package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// TextScanner finds secret spans in a text.
type TextScanner interface {
	Scan(ctx context.Context, text string) ([]Finding, error)
}

// Server serves the scan API. Its zero value is not usable; see NewServer.
type Server struct {
	scanner  TextScanner
	maxBytes int64
	timeout  time.Duration
	log      *slog.Logger
	// slots bounds concurrent requests past the header stage, so a burst
	// queues (within its deadline) instead of thrashing the CPU, and at most
	// cap(slots) bodies are in memory.
	slots chan struct{}
}

// NewServer returns a Server that refuses bodies over maxBytes and gives each
// request timeout to finish, with at most concurrency scans running at once.
func NewServer(scanner TextScanner, maxBytes int64, timeout time.Duration, concurrency int, log *slog.Logger) *Server {
	return &Server{
		scanner:  scanner,
		maxBytes: maxBytes,
		timeout:  timeout,
		log:      log,
		slots:    make(chan struct{}, max(1, concurrency)),
	}
}

// Handler routes POST /scan and GET /healthz.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan", s.scan)
	mux.HandleFunc("GET /healthz", s.healthz)
	return mux
}

type scanRequest struct {
	Text *string `json:"text"`
}

type scanResponse struct {
	Findings []Finding `json:"findings"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// scan answers with spans and rule ids only. Its errors are fixed strings: no
// response or log line carries any part of the body.
//
// A request takes a scan slot before it reads its body, so at most
// cap(slots) bodies are held in memory at once, however many requests the
// client has in flight. A request waiting for a slot holds only its headers.
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	began := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	if r.ContentLength > s.maxBytes {
		s.refuse(w, http.StatusRequestEntityTooLarge, "body too large", began)
		return
	}

	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		s.refuse(w, http.StatusGatewayTimeout, "scan deadline exceeded", began)
		return
	}
	// The handler owns the slot until it hands it to the scan goroutine.
	owned := true
	defer func() {
		if owned {
			<-s.slots
		}
	}()

	var req scanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.maxBytes))
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.refuse(w, http.StatusRequestEntityTooLarge, "body too large", began)
			return
		}
		s.refuse(w, http.StatusBadRequest, "body is not a JSON object with a text string", began)
		return
	}
	if req.Text == nil {
		s.refuse(w, http.StatusBadRequest, "body is not a JSON object with a text string", began)
		return
	}
	text := *req.Text

	type result struct {
		findings []Finding
		err      error
	}
	done := make(chan result, 1)
	owned = false
	go func() {
		// The slot is released when the scan really stops, not when the
		// response is written, so an abandoned scan still counts against
		// the limit until it notices the cancelled context.
		defer func() { <-s.slots }()
		defer func() {
			// A panic here would otherwise kill the process; its value
			// could quote the text, so only its type is kept.
			if p := recover(); p != nil {
				done <- result{err: scanPanic{fmt.Sprintf("%T", p)}}
			}
		}()
		f, err := s.scanner.Scan(ctx, text)
		done <- result{f, err}
	}()

	select {
	case <-ctx.Done():
		s.refuse(w, http.StatusGatewayTimeout, "scan deadline exceeded", began)
	case res := <-done:
		if res.err != nil {
			if errors.Is(res.err, context.DeadlineExceeded) || errors.Is(res.err, context.Canceled) {
				s.refuse(w, http.StatusGatewayTimeout, "scan deadline exceeded", began)
				return
			}
			var p scanPanic
			if errors.As(res.err, &p) {
				s.log.Error("scan panicked", "panic_type", p.valueType, "bytes", len(text))
			} else {
				s.log.Error("scan failed", "error_type", errorType(res.err), "bytes", len(text))
			}
			s.refuse(w, http.StatusInternalServerError, "scan failed", began)
			return
		}
		rules := make([]string, len(res.findings))
		for i, f := range res.findings {
			rules[i] = f.RuleID
		}
		s.log.Info("scan",
			"bytes", len(text),
			"findings", len(res.findings),
			"rule_ids", rules,
			"duration_ms", time.Since(began).Milliseconds())
		writeJSON(w, http.StatusOK, scanResponse{Findings: res.findings})
	}
}

// scanPanic is a recovered panic from a scan, reduced to the panic value's type.
type scanPanic struct{ valueType string }

func (p scanPanic) Error() string { return "scan panicked with a " + p.valueType }

func (s *Server) refuse(w http.ResponseWriter, status int, msg string, began time.Time) {
	s.log.Warn("scan refused", "status", status, "reason", msg, "duration_ms", time.Since(began).Milliseconds())
	writeJSON(w, status, errorResponse{Error: msg})
}

// errorType names an error without its message, which could quote input.
func errorType(err error) string {
	return fmt.Sprintf("%T", err)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
