package main

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// codePointSpan is where secret sits in text as Python would index it.
func codePointSpan(t *testing.T, text, secret string) (int, int) {
	t.Helper()
	i := strings.Index(text, secret)
	if i < 0 {
		t.Fatalf("fixture does not contain its secret")
	}
	start := utf8.RuneCountInString(text[:i])
	return start, start + utf8.RuneCountInString(secret)
}

func TestScanFindsSecretsAtCodePointOffsets(t *testing.T) {
	s := testScanner(t)
	aws, pat, key := fakeAWSKeyID(t), fakeGitHubPAT(t), fakePrivateKey(t)
	awsPair := "\n" + fakeAWSSecretLine(t) + "\n"

	cases := []struct {
		name   string
		prefix string
		secret string
		suffix string
		rule   string
	}{
		{"aws ascii", "aws_access_key_id = ", aws, awsPair, "aws-access-token"},
		{"aws after norwegian", "nøkkel for ærlig åpen tilgang: ", aws, " slutt" + awsPair, "aws-access-token"},
		{"aws after emoji", "🔑🙂 key ", aws, " 👍\r" + awsPair, "aws-access-token"},
		{"pat after crlf lines", "første linje\r\nandre linje æøå\r\ntoken: ", pat, "\r\n", "github-pat"},
		{"pat after astral and combining", "é 𝄞 🇳🇴\r\n", pat, "", "github-pat"},
		{"private key multiline crlf", "blåbær\r\n", strings.ReplaceAll(key, "\n", "\r\n"), "\r\nslutt 🎉", "private-key"},
		{"private key mid text", prose + "here:\n", key, "\n" + prose, "private-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.prefix + tc.secret + tc.suffix
			got, err := s.Scan(context.Background(), text)
			if err != nil {
				t.Fatal(err)
			}
			wantStart, wantEnd := codePointSpan(t, text, tc.secret)
			for _, f := range got {
				if f.RuleID == tc.rule && f.Start == wantStart && f.End == wantEnd {
					return
				}
			}
			t.Fatalf("no %s finding at [%d,%d); got %+v", tc.rule, wantStart, wantEnd, got)
		})
	}
}

// A secret behind an encoding is reported over the encoded text it came from,
// which is what has to be redacted.
func TestScanDecodedSecretSpansEncodedText(t *testing.T) {
	s := testScanner(t)
	encoded := base64.StdEncoding.EncodeToString([]byte("token=" + fakeGitHubPAT(t)))
	text := "æøå 🎉 data: " + encoded + " slutt"
	got, err := s.Scan(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	wantStart, wantEnd := codePointSpan(t, text, encoded)
	if len(got) != 1 || got[0] != (Finding{wantStart, wantEnd, "github-pat"}) {
		t.Fatalf("got %+v, want github-pat at [%d,%d)", got, wantStart, wantEnd)
	}
}

func TestScanPlainProseHasNoFindings(t *testing.T) {
	s := testScanner(t)
	for _, text := range []string{"", prose, strings.Repeat(prose, 50)} {
		got, err := s.Scan(context.Background(), text)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("prose gave findings: %+v", got)
		}
	}
}

func TestScanStopsOnCancelledContext(t *testing.T) {
	s := testScanner(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, prose+fakeGitHubPAT(t)); err == nil {
		t.Fatal("scan with a cancelled context returned no error")
	}
}

// ruleIDShape is the rule id charset the README documents for callers that
// turn rule ids into span types. A Betterleaks update that widens it fails
// here, before a caller rejects a span it cannot name.
var ruleIDShape = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,44}$`)

func TestRuleIDsKeepDocumentedShape(t *testing.T) {
	s := testScanner(t)
	for id := range s.detector.Config.Rules {
		if !ruleIDShape.MatchString(id) {
			t.Errorf("rule id %q is outside ^[a-z0-9][a-z0-9.-]{0,44}$", id)
		}
	}
}

func TestLineStarts(t *testing.T) {
	cases := []struct {
		text string
		want []int
	}{
		{"", []int{0}},
		{"abc", []int{0}},
		{"a\nb", []int{0, 2}},
		{"a\r\nb\r\n", []int{0, 3, 6}},
		{"æ\nø", []int{0, 3}},
	}
	for _, tc := range cases {
		got := lineStarts(tc.text)
		if len(got) != len(tc.want) {
			t.Fatalf("lineStarts(%q) = %v, want %v", tc.text, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("lineStarts(%q) = %v, want %v", tc.text, got, tc.want)
			}
		}
	}
}

func TestByteSpan(t *testing.T) {
	// "ab\r\ncdé\nf": lines start at bytes 0, 4 and 9.
	text := "ab\r\ncdé\nf"
	starts := lineStarts(text)
	cases := []struct {
		name                string
		startLine, startCol int
		endLine, endCol     int
		wantStart, wantEnd  int
		wantOK              bool
	}{
		{"first line", 1, 1, 1, 2, 0, 2, true},
		{"includes cr", 1, 2, 1, 3, 1, 3, true},
		{"second line multibyte", 2, 1, 2, 4, 4, 8, true},
		{"across lines", 1, 2, 3, 1, 1, 10, true},
		{"path-only finding", 0, 0, 0, 0, 0, 0, false},
		{"line past end", 4, 1, 4, 1, 0, 0, false},
		{"end past text", 3, 1, 3, 5, 0, 0, false},
		{"empty span", 1, 2, 1, 1, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, e, ok := byteSpan(starts, len(text), tc.startLine, tc.startCol, tc.endLine, tc.endCol)
			if ok != tc.wantOK || (ok && (s != tc.wantStart || e != tc.wantEnd)) {
				t.Fatalf("got [%d,%d) ok=%v, want [%d,%d) ok=%v", s, e, ok, tc.wantStart, tc.wantEnd, tc.wantOK)
			}
		})
	}
}

func TestRuneOffsetsAndWiden(t *testing.T) {
	text := "aæ😀\r\nb" // bytes: a=0 æ=1..2 😀=3..6 \r=7 \n=8 b=9
	got := runeOffsets(text, []int{9, 0, 3, 1, 7, 10})
	want := map[int]int{0: 0, 1: 1, 3: 2, 7: 3, 9: 5, 10: 6}
	for b, r := range want {
		if got[b] != r {
			t.Fatalf("byte %d -> code point %d, want %d", b, got[b], r)
		}
	}
	if s, e := widen(text, 2, 5); s != 1 || e != 7 {
		t.Fatalf("widen(2,5) = [%d,%d), want [1,7)", s, e)
	}
	if s, e := widen(text, 3, 7); s != 3 || e != 7 {
		t.Fatalf("widen on boundaries moved: [%d,%d)", s, e)
	}
}
