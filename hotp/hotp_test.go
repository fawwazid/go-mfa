package hotp

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// RFC 4226 Test Vectors
// Secret = 12345678901234567890 (20 bytes)
// We need to base32 encode this secret to use with our library.
// 0x3132333435363738393031323334353637383930 -> GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
const rfcSecretHex = "12345678901234567890"
const rfcSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestRFC4226Vectors(t *testing.T) {
	// Vectors from RFC 4226 Appendix D
	vectors := []struct {
		counter uint64
		code    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, v := range vectors {
		// Test Generate
		got, err := GenerateCode(rfcSecretBase32, v.counter, WithLength(6))
		if err != nil {
			t.Errorf("GenerateCode(counter=%d) error = %v", v.counter, err)
			continue
		}
		if got != v.code {
			t.Errorf("GenerateCode(counter=%d) = %s, want %s", v.counter, got, v.code)
		}

		// Test Validate
		if !Validate(v.code, rfcSecretBase32, v.counter, WithLength(6)) {
			t.Errorf("Validate(counter=%d) returned false for valid code", v.counter)
		}
	}
}

func TestAlgorithms(t *testing.T) {
	// Simple sanity checks for other algos (SHA256, SHA512)
	// We don't have standard RFC vectors readily available for these specific non-sha1 HOTP in the RFC4226 doc itself,
	// but we check that they run and produce correct lengths.

	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // valid base32

	t.Run("SHA256", func(t *testing.T) {
		code, err := GenerateCode(secret, 0, WithAlgorithm(sha256.New), WithLength(8))
		if err != nil {
			t.Fatalf("Failed to generate SHA256: %v", err)
		}
		if len(code) != 8 {
			t.Errorf("Length expected 8, got %d", len(code))
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		code, err := GenerateCode(secret, 0, WithAlgorithm(sha512.New), WithLength(6))
		if err != nil {
			t.Fatalf("Failed to generate SHA512: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("Length expected 6, got %d", len(code))
		}
	})
}
