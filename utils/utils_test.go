package utils

import (
	"encoding/binary"
	"testing"
	"unicode/utf8"
)

func TestCryptoRandomString(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		charset string
		wantErr bool
	}{
		{"Valid numeric", 6, "1234567890", false},
		{"Valid alpha", 10, "abc", false},
		{"Zero length", 0, "abc", true},
		{"Empty charset", 6, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CryptoRandomString(tt.length, tt.charset)
			if (err != nil) != tt.wantErr {
				t.Errorf("CryptoRandomString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != tt.length {
					t.Errorf("CryptoRandomString() length = %v, want %v", len(got), tt.length)
				}
				// Check content (basic check)
				for _, char := range got {
					found := false
					for _, c := range tt.charset {
						if char == c {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("CryptoRandomString() contained invalid char %c", char)
					}
				}
			}
		})
	}
}

func TestCryptoRandomStringUnicode(t *testing.T) {
	const charset = "αβ🙂"
	got, err := CryptoRandomString(32, charset)
	if err != nil {
		t.Fatalf("CryptoRandomString() error = %v", err)
	}
	if count := utf8.RuneCountInString(got); count != 32 {
		t.Fatalf("CryptoRandomString() rune count = %d, want 32", count)
	}
	for _, char := range got {
		found := false
		for _, allowed := range charset {
			if char == allowed {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("CryptoRandomString() contained invalid rune %q", char)
		}
	}

	if _, err := CryptoRandomString(1, string([]byte{0xff})); err == nil {
		t.Fatal("CryptoRandomString() accepted invalid UTF-8")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"123", "123", true},
		{"123", "124", false},
		{"123", "1234", false},
		{"", "", true},
		{"a", "b", false},
	}
	for _, tt := range tests {
		if got := ConstantTimeCompare(tt.a, tt.b); got != tt.want {
			t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestItob(t *testing.T) {
	val := uint64(0x0102030405060708)
	expected := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	got := Itob(val)
	if len(got) != 8 {
		t.Errorf("Itob length = %d, want 8", len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("Itob byte %d = %x, want %x", i, got[i], expected[i])
		}
	}
	// Verify big endian
	if binary.BigEndian.Uint64(got) != val {
		t.Errorf("Itob result is not big endian")
	}
}
