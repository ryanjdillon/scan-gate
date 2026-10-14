package main

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// lineStarts returns the byte offset at which each line of text begins, using
// the same rule as Betterleaks: a line ends after '\n', so a '\r' before it
// stays part of the line and counts as one byte of its columns.
func lineStarts(text string) []int {
	starts := []int{0}
	for i := 0; ; {
		j := strings.IndexByte(text[i:], '\n')
		if j < 0 {
			return starts
		}
		i += j + 1
		starts = append(starts, i)
	}
}

// byteSpan turns a Betterleaks finding's 1-based line numbers and byte columns
// into a half-open byte range of text. StartColumn is 1-based inclusive and
// EndColumn is the 1-based column of the last byte, so the exclusive end is
// the line start plus EndColumn. ok is false for a finding without a usable
// location (a path-only rule, or a span outside text).
func byteSpan(starts []int, textLen, startLine, startCol, endLine, endCol int) (start, end int, ok bool) {
	if startLine < 1 || endLine < startLine || endLine > len(starts) || startCol < 1 || endCol < 0 {
		return 0, 0, false
	}
	start = starts[startLine-1] + startCol - 1
	end = starts[endLine-1] + endCol
	if start < 0 || end > textLen || end <= start {
		return 0, 0, false
	}
	return start, end, true
}

// runeOffsets maps byte offsets into text to Unicode code point offsets, the
// indices a Python str uses. Offsets must sit on code point boundaries (see
// widen). It walks text once whatever the number of offsets.
func runeOffsets(text string, byteOffsets []int) map[int]int {
	sorted := append([]int(nil), byteOffsets...)
	sort.Ints(sorted)
	out := make(map[int]int, len(sorted))
	runes, pos := 0, 0
	for _, b := range sorted {
		for pos < b && pos < len(text) {
			_, size := utf8.DecodeRuneInString(text[pos:])
			pos += size
			runes++
		}
		out[b] = runes
	}
	return out
}

// widen moves start back and end forward to code point boundaries, so a span
// never splits a character and always covers the whole match.
func widen(text string, start, end int) (int, int) {
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return start, end
}
