package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
)

// Every credential in these tests is generated at test time. None is real, and
// none is a vendor's documented example value (a ruleset may allowlist those).

const (
	base32Upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func randomFrom(t testing.TB, alphabet string, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, b := range buf {
		sb.WriteByte(alphabet[int(b)%len(alphabet)])
	}
	return sb.String()
}

// fakeAWSKeyID is shaped like an AWS access key id: AKIA and 16 base32 characters.
func fakeAWSKeyID(t testing.TB) string {
	t.Helper()
	for {
		id := "AKIA" + randomFrom(t, base32Upper, 16)
		if !strings.HasSuffix(id, "EXAMPLE") {
			return id
		}
	}
}

// fakeAWSSecretLine is a generated secret-access-key assignment. The ruleset
// reports an access key id only with its secret key nearby, as a pair.
func fakeAWSSecretLine(t testing.TB) string {
	t.Helper()
	return "aws_secret_access_key = " + randomFrom(t, alphanumeric+"/+", 40)
}

// fakeGitHubPAT is shaped like a classic GitHub personal access token.
func fakeGitHubPAT(t testing.TB) string {
	t.Helper()
	return "ghp_" + randomFrom(t, alphanumeric, 36)
}

// fakePrivateKey is a freshly generated P-256 key in PKCS#8 PEM, thrown away
// when the test ends.
func fakePrivateKey(t testing.TB) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "\n")
}

var (
	sharedScanner     *Scanner
	sharedScannerErr  error
	sharedScannerOnce sync.Once
)

// testScanner builds the real detector once for the whole test binary.
func testScanner(t testing.TB) *Scanner {
	t.Helper()
	sharedScannerOnce.Do(func() { sharedScanner, sharedScannerErr = NewScanner() })
	if sharedScannerErr != nil {
		t.Fatal(sharedScannerErr)
	}
	return sharedScanner
}

const prose = "Møtet ble flyttet til torsdag. Ta med rapporten om blåbærsyltetøy, " +
	"budsjettet for neste kvartal og forslaget til nytt kontor. 🎉 " +
	"The meeting moved to Thursday; please bring the quarterly report and the office proposal.\r\n"
