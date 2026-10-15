package totp

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Secret Generation helper
func getRFCSecret(t *testing.T, size int) string {
	// RFC 6238 Appendix B: The secret is a string of "1234567890..." repeated.
	// SHA1: 20 bytes
	// SHA256: 32 bytes
	// SHA512: 64 bytes
	pattern := "12345678901234567890"
	raw := ""
	for len(raw) < size {
		raw += pattern
	}
	raw = raw[:size]
	return base32.StdEncoding.EncodeToString([]byte(raw))
}

func TestRFC6238Vectors(t *testing.T) {
	// Vectors from RFC 6238 Appendix B (Table 1) - All are 8 digits

	// Mode: SHA1
	testsSha1 := []struct {
		ts   int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	secretSha1 := getRFCSecret(t, 20)
	for _, v := range testsSha1 {
		tm := time.Unix(v.ts, 0)
		got, err := GenerateCode(secretSha1, WithTime(tm), WithLength(8))
		if err != nil {
			t.Errorf("SHA1 GenerateCode(ts=%d) error = %v", v.ts, err)
			continue
		}
		if got != v.code {
			t.Errorf("SHA1 GenerateCode(ts=%d) = %s, want %s", v.ts, got, v.code)
		}
	}

	// Mode: SHA256
	testsSha256 := []struct {
		ts   int64
		code string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	secretSha256 := getRFCSecret(t, 32)
	for _, v := range testsSha256 {
		tm := time.Unix(v.ts, 0)
		got, err := GenerateCode(secretSha256, WithTime(tm), WithAlgorithm(sha256.New), WithLength(8))
		if err != nil {
			t.Errorf("SHA256 GenerateCode(ts=%d) error = %v", v.ts, err)
			continue
		}
		if got != v.code {
			t.Errorf("SHA256 GenerateCode(ts=%d) = %s, want %s", v.ts, got, v.code)
		}
	}

	// Mode: SHA512
	testsSha512 := []struct {
		ts   int64
		code string
	}{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
		{20000000000, "47863826"},
	}

	secretSha512 := getRFCSecret(t, 64)
	for _, v := range testsSha512 {
		tm := time.Unix(v.ts, 0)
		got, err := GenerateCode(secretSha512, WithTime(tm), WithAlgorithm(sha512.New), WithLength(8))
		if err != nil {
			t.Errorf("SHA512 GenerateCode(ts=%d) error = %v", v.ts, err)
			continue
		}
		if got != v.code {
			t.Errorf("SHA512 GenerateCode(ts=%d) = %s, want %s", v.ts, got, v.code)
		}
	}
}

func TestValidateSkew(t *testing.T) {
	// Using default settings (30s period, SHA1, 6 digits)
	secret := getRFCSecret(t, 20)
	now := time.Now()

	// Skew = 1 (default) means we accept [now-30s, now, now+30s]

	// 1. Current time -> Valid
	codeNow, _ := GenerateCode(secret, WithTime(now))
	if !Validate(codeNow, secret, WithTime(now)) {
		t.Error("Validation failed for current time")
	}

	// 2. Previous interval (-30s) -> Valid
	codePrev, _ := GenerateCode(secret, WithTime(now.Add(-30*time.Second)))
	if !Validate(codePrev, secret, WithTime(now)) {
		t.Error("Validation failed for previous interval (accepting skew)")
	}

	// 3. Next interval (+30s) -> Valid
	codeNext, _ := GenerateCode(secret, WithTime(now.Add(30*time.Second)))
	if !Validate(codeNext, secret, WithTime(now)) {
		t.Error("Validation failed for next interval (accepting skew)")
	}

	// 4. Too old (-65s) -> Invalid
	codeOld, _ := GenerateCode(secret, WithTime(now.Add(-65*time.Second)))
	if Validate(codeOld, secret, WithTime(now)) {
		t.Error("Validation passed for expired code (outside skew)")
	}
}

func TestGenerateURL(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	url := GenerateURL("user", "issuer", secret)
	// Expect standard keys
	expectedSubstrings := []string{
		"otpauth://totp/issuer:user",
		"secret=JBSWY3DPEHPK3PXP",
		"issuer=issuer",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	}
	for _, sub := range expectedSubstrings {
		if !strings.Contains(url, sub) {
			t.Errorf("URL missing %s. Got: %s", sub, url)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	// 1. Default (SHA1 -> 20 bytes -> 32 chars base32)
	sec1, err := GenerateSecret(nil)
	if err != nil {
		t.Fatalf("GenerateSecret(nil) error: %v", err)
	}
	if len(sec1) == 0 {
		t.Error("GenerateSecret(nil) returned empty string")
	}
	// Base32 standard encoding of 20 bytes is 32 chars
	// (20 * 8) / 5 = 32
	if len(sec1) != 32 {
		t.Errorf("GenerateSecret(nil) length = %d, want 32", len(sec1))
	}

	// 2. SHA256 (32 bytes -> 52 chars without padding)
	sec2, err := GenerateSecret(sha256.New)
	if err != nil {
		t.Fatalf("GenerateSecret(sha256) error: %v", err)
	}
	if len(sec2) == 0 {
		t.Error("GenerateSecret(sha256) returned empty")
	}
	if len(sec2) != 52 || strings.Contains(sec2, "=") {
		t.Errorf("GenerateSecret(sha256) = %q, want 52 unpadded characters", sec2)
	}

	// 3. SHA512 (64 bytes -> 103-104 chars)
	sec3, err := GenerateSecret(sha512.New)
	if err != nil {
		t.Fatalf("GenerateSecret(sha512) error: %v", err)
	}
	if len(sec3) == 0 {
		t.Error("GenerateSecret(sha512) returned empty")
	}
	if len(sec3) != 103 || strings.Contains(sec3, "=") {
		t.Errorf("GenerateSecret(sha512) = %q, want 103 unpadded characters", sec3)
	}
}

func TestGenerateEnrollment(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	enroll, err := GenerateEnrollment("user@example.com", "GoMFA", secret, 256)
	if err != nil {
		t.Fatalf("GenerateEnrollment error: %v", err)
	}

	if enroll == nil {
		t.Fatal("GenerateEnrollment returned nil struct")
	}

	// Check Secret
	if enroll.Secret != secret {
		t.Errorf("Enrollment.Secret = %s, want %s", enroll.Secret, secret)
	}

	// Check URL
	if !strings.Contains(enroll.URL, "otpauth://totp/GoMFA:user@example.com") {
		t.Errorf("Enrollment.URL malformed: %s", enroll.URL)
	}

	// Check Image (basic check)
	if enroll.Image == nil {
		t.Error("Enrollment.Image is nil")
	}
	bounds := enroll.Image.Bounds()
	if bounds.Dx() != 256 || bounds.Dy() != 256 {
		t.Errorf("Enrollment.Image size = %dx%d, want 256x256", bounds.Dx(), bounds.Dy())
	}
}

func TestInvalidConfiguration(t *testing.T) {
	secret := getRFCSecret(t, 20)

	if _, err := GenerateCode(secret, WithPeriod(0)); !errors.Is(err, ErrInvalidPeriod) {
		t.Fatalf("GenerateCode() error = %v, want %v", err, ErrInvalidPeriod)
	}
	if Validate("123456", secret, WithPeriod(0)) {
		t.Fatal("Validate() accepted a zero period")
	}
	if _, err := GenerateCode(secret, WithTime(time.Unix(-1, 0))); err == nil {
		t.Fatal("GenerateCode() accepted a time before the Unix epoch")
	}
	if Validate("123456", secret, WithTime(time.Unix(-1, 0))) {
		t.Fatal("Validate() accepted a time before the Unix epoch")
	}
	if _, err := GenerateCode(secret, WithAlgorithm(md5.New)); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("GenerateCode() error = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
	if uri := GenerateURL("user", "issuer", secret, WithAlgorithm(md5.New)); uri != "" {
		t.Fatalf("GenerateURL() returned URI for unsupported algorithm: %s", uri)
	}
	if Validate("123456", secret, WithSkew(MaxSkew+1)) {
		t.Fatal("Validate() accepted an excessive skew")
	}
	if _, err := GenerateQR("user", "issuer", secret, MaxQRSize+1); !errors.Is(err, ErrInvalidQRSize) {
		t.Fatalf("GenerateQR() error = %v, want %v", err, ErrInvalidQRSize)
	}
	if _, err := GenerateURLChecked("bad:account", "issuer", secret); !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("GenerateURLChecked() error = %v, want %v", err, ErrInvalidLabel)
	}
}
