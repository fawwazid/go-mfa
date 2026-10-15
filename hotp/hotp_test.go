package hotp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
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

func TestInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want error
	}{
		{"zero length", []Option{WithLength(0)}, ErrInvalidLength},
		{"excessive length", []Option{WithLength(MaxLength + 1)}, ErrInvalidLength},
		{"nil algorithm", []Option{WithAlgorithm(nil)}, ErrInvalidAlgorithm},
		{"short hash", []Option{WithAlgorithm(md5.New)}, ErrInvalidHash},
		{"nil encoder", []Option{WithEncoder(nil)}, ErrInvalidEncoder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateCode(rfcSecretBase32, 0, tt.opts...)
			if err == nil || err.Error() != tt.want.Error() {
				t.Fatalf("GenerateCode() error = %v, want %v", err, tt.want)
			}
		})
	}

	if _, err := GenerateCode("", 0); err == nil {
		t.Fatal("GenerateCode() accepted an empty secret")
	}
	if _, err := GenerateCodeFromKey(nil, 0); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("GenerateCodeFromKey() error = %v, want %v", err, ErrInvalidSecret)
	}
	if _, err := GenerateCode(rfcSecretBase32+"====", 0, WithAlgorithm(sha1.New)); err != nil {
		t.Fatalf("GenerateCode() rejected a padded secret: %v", err)
	}
	if !Validate("755224", rfcSecretBase32, 0, nil) {
		t.Fatal("Validate() rejected a nil option")
	}
}
