package totp

import (
	"crypto"
	"encoding/base32"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func getRFCSecret(t *testing.T, size int) string {
	t.Helper()
	raw := strings.Repeat("1234567890", 7)[:size]
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(raw))
}

func TestRFC6238Vectors(t *testing.T) {
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	for _, tc := range []struct {
		hash  crypto.Hash
		size  int
		codes []string
	}{
		{crypto.SHA256, 32, []string{"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"}},
		{crypto.SHA512, 64, []string{"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}},
	} {
		secret := getRFCSecret(t, tc.size)
		for i, seconds := range times {
			code, err := GenerateCode(secret, WithTime(time.Unix(seconds, 0)), WithAlgorithm(tc.hash), WithLength(8))
			if err != nil || code != tc.codes[i] {
				t.Fatalf("hash=%v time=%d code=%q err=%v", tc.hash, seconds, code, err)
			}
		}
	}
}

func TestValidateSkew(t *testing.T) {
	secret := getRFCSecret(t, 32)
	now := time.Unix(1234567890, 0)
	for _, offset := range []int64{-30, 0, 30} {
		code, err := GenerateCode(secret, WithTime(now.Add(time.Duration(offset)*time.Second)))
		if err != nil {
			t.Fatal(err)
		}
		if !Validate(code, secret, WithTime(now)) {
			t.Fatalf("rejected skew %d", offset)
		}
	}
	code, err := GenerateCode(secret, WithTime(now.Add(-90*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if Validate(code, secret, WithTime(now)) {
		t.Fatal("accepted expired code")
	}
}

func TestValidateAtMaximumUnixTime(t *testing.T) {
	secret := getRFCSecret(t, 32)
	opts := []Option{WithTime(time.Unix(math.MaxInt64, 0)), WithPeriod(1), WithSkew(MaxSkew)}
	code, err := GenerateCode(secret, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(code, secret, opts...) {
		t.Fatal("rejected code at the maximum supported Unix time")
	}
}

func TestGenerateURL(t *testing.T) {
	secret := getRFCSecret(t, 32)
	uri, err := GenerateURL("user", "issuer", secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"otpauth://totp/issuer:user", "secret=" + secret, "issuer=issuer", "algorithm=SHA256", "digits=6", "period=30"} {
		if !strings.Contains(uri, part) {
			t.Fatalf("missing %q in %q", part, uri)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	for _, tc := range []struct {
		hash   crypto.Hash
		length int
	}{{crypto.SHA256, 52}, {crypto.SHA512, 103}} {
		secret, err := GenerateSecret(tc.hash)
		if err != nil || len(secret) != tc.length || strings.Contains(secret, "=") {
			t.Fatalf("secret=%q, %v", secret, err)
		}
	}
	for _, hash := range []crypto.Hash{0, crypto.SHA1, crypto.MD5} {
		if _, err := GenerateSecret(hash); err == nil {
			t.Fatal("accepted unsupported hash", hash)
		}
	}
}

func TestGenerateEnrollment(t *testing.T) {
	secret := getRFCSecret(t, 32)
	enrollment, err := GenerateEnrollment("user@example.com", "App", secret, 256)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Secret != secret || !strings.Contains(enrollment.URL, "algorithm=SHA256") {
		t.Fatal("incorrect enrollment")
	}
	if enrollment.Image == nil || enrollment.Image.Bounds().Dx() != 256 || enrollment.Image.Bounds().Dy() != 256 {
		t.Fatal("incorrect QR size")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	secret := getRFCSecret(t, 32)
	if _, err := GenerateCode(secret, WithPeriod(0)); !errors.Is(err, ErrInvalidPeriod) {
		t.Fatal(err)
	}
	if Validate("123456", secret, WithPeriod(0)) {
		t.Fatal("accepted invalid period")
	}
	if _, err := GenerateCode(secret, WithTime(time.Unix(-1, 0))); !errors.Is(err, ErrInvalidTime) {
		t.Fatal(err)
	}
	if Validate("123456", secret, WithSkew(MaxSkew+1)) {
		t.Fatal("accepted invalid skew")
	}
	for _, hash := range []crypto.Hash{0, crypto.SHA1, crypto.MD5} {
		if _, err := GenerateCode(secret, WithAlgorithm(hash)); err == nil {
			t.Fatal("accepted unsupported hash")
		}
		if _, err := GenerateURL("user", "issuer", secret, WithAlgorithm(hash)); err == nil {
			t.Fatal("suppressed URI error")
		}
	}
	if _, err := GenerateQR("user", "issuer", secret, MaxQRSize+1); !errors.Is(err, ErrInvalidQRSize) {
		t.Fatal(err)
	}
	if _, err := GenerateURL("bad:account", "issuer", secret); !errors.Is(err, ErrInvalidLabel) {
		t.Fatal(err)
	}
}
