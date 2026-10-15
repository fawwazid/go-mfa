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

// GenericRandomBytes generates a slice of random bytes of the given size.
func GenericRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be greater than 0")
	}
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// CryptoRandomString generates a cryptographically secure random string of the given length
// using the characters from the provided charset.
// It returns an error if length is <= 0 or charset is empty.
func CryptoRandomString(length int, charset string) (string, error) {
	if length <= 0 {
		return "", errors.New("length must be greater than 0")
	}
	if charset == "" {
		return "", errors.New("charset cannot be empty")
	}

	if !utf8.ValidString(charset) {
		return "", errors.New("charset must contain valid UTF-8")
	}
	runes := []rune(charset)
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

// ConstantTimeCompare compares two strings in constant time to avoid timing attacks.
// It returns true if the strings are identical, false otherwise.
// This is critical for validating sensitive tokens like OTPs.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Itob converts a uint64 to an 8-byte slice in Big Endian byte order.
// This is typically used for converting the counter or time value before hashing.
func Itob(i uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)
	return buf
}
