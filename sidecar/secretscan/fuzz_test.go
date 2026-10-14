package main

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzScan plants a generated GitHub token on its own line between arbitrary
// noise (multi-byte text, CRLF, encoded runs, invalid UTF-8) and checks that
// it is reported at its code point offsets and that every span is in range.
func FuzzScan(f *testing.F) {
	for _, seed := range []string{
		"", "æøå", "🎉\r\n", "\r", "é 🇳🇴 𝄞",
		base64.StdEncoding.EncodeToString([]byte("noise æøå 🎉")),
		"\xff\xfe\xfd", "line\r\nline\nline\r",
	} {
		f.Add(seed, seed)
	}
	s := testScanner(f)
	pat := fakeGitHubPAT(f)
	f.Fuzz(func(t *testing.T, before, after string) {
		line := "token " + pat
		text := before + "\n" + line + "\n" + after
		got, err := s.Scan(context.Background(), text)
		if err != nil {
			t.Fatal(err)
		}
		total := utf8.RuneCountInString(text)
		for _, g := range got {
			if g.Start < 0 || g.Start >= g.End || g.End > total {
				t.Fatalf("span [%d,%d) outside text of %d code points", g.Start, g.End, total)
			}
		}
		i := len(before) + 1 + strings.Index(line, pat)
		want := Finding{
			Start:  utf8.RuneCountInString(text[:i]),
			End:    utf8.RuneCountInString(text[:i+len(pat)]),
			RuleID: "github-pat",
		}
		for _, g := range got {
			if g == want {
				return
			}
		}
		t.Fatalf("token not reported at [%d,%d): %+v", want.Start, want.End, got)
	})
}
