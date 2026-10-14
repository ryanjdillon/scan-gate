package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/rs/zerolog"
)

// maxDecodeDepth matches the Betterleaks CLI default, so a secret hidden
// behind base64, hex or percent encoding is still found. A decoded finding's
// span covers the encoded text it came from.
const maxDecodeDepth = 5

// Finding is one secret span: a half-open range of Unicode code points into
// the scanned text and the rule that matched. It deliberately has no field for
// the matched value.
type Finding struct {
	Start  int    `json:"start"`
	End    int    `json:"end"`
	RuleID string `json:"rule_id"`
}

// Scanner holds a Betterleaks detector built once from the default ruleset.
// Scan is safe for concurrent use.
type Scanner struct {
	detector *detect.Detector
}

// NewScanner builds the detector and compiles every rule up front, so a bad
// ruleset fails startup instead of the first request, and the first request
// does not pay for compilation.
func NewScanner() (*Scanner, error) {
	// Betterleaks logs a finding's secret at trace level; keep its logger to
	// errors so no matched value can reach the log.
	logging.Logger = logging.Logger.Level(zerolog.ErrorLevel)

	cfg, err := config.Default()
	if err != nil {
		return nil, fmt.Errorf("load default ruleset: %w", err)
	}
	// The zero ValidationOptions leaves validation off: no finding is ever
	// checked against its provider.
	d := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
	if d == nil {
		return nil, fmt.Errorf("build detector")
	}
	d.MaxDecodeDepth = maxDecodeDepth
	d.SkipFindingAppend = true
	for id, rule := range cfg.Rules {
		if rule.Regex == nil {
			continue
		}
		if err := rule.Regex.Compile(); err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", id, err)
		}
	}
	if d.Tokenizer() == nil {
		return nil, fmt.Errorf("load tokenizer")
	}
	return &Scanner{detector: d}, nil
}

// RuleCount is the number of rules in the loaded ruleset.
func (s *Scanner) RuleCount() int {
	return len(s.detector.Config.Rules)
}

// Scan returns the secret spans in text, sorted by start, with duplicates
// removed. It stops early when ctx is done, returning ctx's error.
func (s *Scanner) Scan(ctx context.Context, text string) ([]Finding, error) {
	//nolint:staticcheck // DetectContext is the context-aware single-fragment call in v1.
	raw := s.detector.DetectContext(ctx, sources.Fragment{Raw: text})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return spans(text, raw)
}

type located struct {
	start, end int
	ruleID     string
}

// spans converts findings' line/byte-column locations to code point offsets.
// A finding whose location does not fit text is an error rather than dropped,
// so the caller refuses the request instead of passing a secret it could not
// place. (Path-only rules, which have no location, cannot fire: the scanned
// fragment has no path.)
func spans(text string, findings []report.Finding) ([]Finding, error) {
	if len(findings) == 0 {
		return []Finding{}, nil
	}
	starts := lineStarts(text)
	byteSpans := make([]located, 0, len(findings))
	offsets := make([]int, 0, 2*len(findings))
	for _, f := range findings {
		start, end, ok := byteSpan(starts, len(text), f.StartLine, f.StartColumn, f.EndLine, f.EndColumn)
		if !ok {
			return nil, fmt.Errorf("finding for rule %s has no valid location", f.RuleID)
		}
		start, end = widen(text, start, end)
		byteSpans = append(byteSpans, located{start, end, f.RuleID})
		offsets = append(offsets, start, end)
	}
	runeAt := runeOffsets(text, offsets)
	out := make([]Finding, 0, len(byteSpans))
	seen := make(map[Finding]struct{}, len(byteSpans))
	for _, b := range byteSpans {
		f := Finding{Start: runeAt[b.start], End: runeAt[b.end], RuleID: b.ruleID}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out, nil
}
