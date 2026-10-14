package main

import (
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// syntheticBody is about size bytes of mixed Norwegian and English prose with
// CRLF line ends, emoji, and a generated GitHub token every 16 KiB, so the
// keyword prefilter, the rule regexes and the offset conversion all run.
func syntheticBody(b *testing.B, size int) string {
	var sb strings.Builder
	for sb.Len() < size {
		if sb.Len()%(16<<10) < len(prose) {
			sb.WriteString("token " + fakeGitHubPAT(b) + "\r\n")
		}
		sb.WriteString(prose)
	}
	return sb.String()[:size]
}

// BenchmarkScan measures one POST /scan through the handler (JSON decode,
// detection, offset conversion, JSON encode) and reports p50 and p99 latency.
func BenchmarkScan(b *testing.B) {
	h := realHandler(b)
	for _, size := range []struct {
		name  string
		bytes int
	}{{"1KB", 1 << 10}, {"64KB", 64 << 10}, {"1MB", 1 << 20}} {
		b.Run(size.name, func(b *testing.B) {
			body := scanBody(b, syntheticBody(b, size.bytes))
			b.SetBytes(int64(len(body)))
			samples := make([]time.Duration, 0, b.N)
			for b.Loop() {
				began := time.Now()
				rec := post(h, body)
				samples = append(samples, time.Since(began))
				if rec.Code != http.StatusOK {
					b.Fatalf("status %d: %s", rec.Code, rec.Body)
				}
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			pct := func(p float64) float64 {
				return float64(samples[int(p*float64(len(samples)-1))].Microseconds()) / 1000
			}
			b.ReportMetric(pct(0.50), "p50-ms")
			b.ReportMetric(pct(0.99), "p99-ms")
		})
	}
}
