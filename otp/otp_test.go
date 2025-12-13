package otp

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		code, err := Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if len(code) != DefaultLength {
			t.Errorf("Generate() length = %d, want %d", len(code), DefaultLength)
		}
		// Default digits
		for _, c := range code {
			if !strings.ContainsRune(Digits, c) {
				t.Errorf("Generate() contained invalid char %c", c)
			}
		}
	})

	t.Run("Custom Length and Charset", func(t *testing.T) {
		code, err := Generate(WithLength(10), WithLetters())
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if len(code) != 10 {
			t.Errorf("Generate() length = %d, want 10", len(code))
		}
		for _, c := range code {
			if !strings.ContainsRune(Letters, c) {
				t.Errorf("Generate() contained invalid char %c", c)
			}
		}
	})

	t.Run("AlphaNumeric", func(t *testing.T) {
		code, err := Generate(WithAlphaNumeric())
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if len(code) != DefaultLength {
			t.Errorf("Generate() length = %d", len(code))
		}
	})

	t.Run("Invalid Options", func(t *testing.T) {
		// Length 0
		_, err := Generate(WithLength(0))
		if err == nil {
			t.Error("Generate() expected error for length 0")
		}
		// Empty charset
		_, err = Generate(WithCharset(""))
		if err == nil {
			t.Error("Generate() expected error for empty charset")
		}
	})
}

func TestValidate(t *testing.T) {
	if !Validate("123", "123") {
		t.Error("Validate() should be true for matches")
	}
	if Validate("123", "124") {
		t.Error("Validate() should be false for mismatches")
	}
}
