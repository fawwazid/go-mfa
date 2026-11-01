// Package utils provides common utility functions for the MFA library,
// including secure random string generation and constant-time comparisons.
package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"unicode/utf8"
)

const (
	// MaxRandomBytes bounds allocations made by GenericRandomBytes.
	MaxRandomBytes = 1 << 20
	// MaxRandomStringLength bounds allocations made by CryptoRandomString.
	MaxRandomStringLength = 1024
	// MaxRandomStringBytes bounds UTF-8 output from CryptoRandomString.
	MaxRandomStringBytes = MaxRandomStringLength * utf8.UTFMax
	// MaxRandomCharsetSize bounds the rune set used by CryptoRandomString.
	MaxRandomCharsetSize = 4096
)

// GenericRandomBytes generates a slice of at most MaxRandomBytes random bytes.
func GenericRandomBytes(size int) ([]byte, error) {
	if size <= 0 || size > MaxRandomBytes {
		return nil, errors.New("size must be between 1 and MaxRandomBytes")
	}
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// CryptoRandomString generates a cryptographically secure random string of the given length
// using the characters from the provided charset.
// It rejects duplicate runes and returns an error for values outside the
// documented length and charset bounds.
func CryptoRandomString(length int, charset string) (string, error) {
	if length <= 0 || length > MaxRandomStringLength {
		return "", errors.New("length must be between 1 and MaxRandomStringLength")
	}
	if charset == "" {
		return "", errors.New("charset cannot be empty")
	}
	if len(charset) > MaxRandomCharsetSize*utf8.UTFMax {
		return "", errors.New("charset exceeds MaxRandomCharsetSize")
	}

	if !utf8.ValidString(charset) {
		return "", errors.New("charset must contain valid UTF-8")
	}
	runes := []rune(charset)
	if len(runes) > MaxRandomCharsetSize {
		return "", errors.New("charset exceeds MaxRandomCharsetSize")
	}
	seen := make(map[rune]struct{}, len(runes))
	for _, r := range runes {
		if _, ok := seen[r]; ok {
			return "", errors.New("charset must not contain duplicate characters")
		}
		seen[r] = struct{}{}
	}
	result := make([]rune, length)
	charsetLen := big.NewInt(int64(len(runes)))

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = runes[num.Int64()]
	}

	return string(result), nil
}

// ConstantTimeCompare compares bounded, equal-length strings in constant time.
// Inputs longer than MaxRandomStringBytes are rejected before allocation.
func ConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) || len(a) > MaxRandomStringBytes {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Itob converts a uint64 to an 8-byte slice in Big Endian byte order.
func Itob(i uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)
	return buf
}
