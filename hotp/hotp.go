// Package hotp implements the HMAC-based One-Time Password algorithm as defined in RFC 4226.
package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"

	"github.com/fawwazid/go-mfa/utils"
)

// Default settings for HOTP.
const (
	DefaultLength = 6
	DefaultAlgo   = "sha1"
)

// Config represents the configuration for HOTP generation.
type Config struct {
	Length    int
	Algorithm func() hash.Hash
	Encoder   *base32.Encoding
}

// Option is a functional option to configure the HOTP generator.
type Option func(*Config)

// WithLength sets the length of the generated OTP.
func WithLength(l int) Option {
	return func(c *Config) {
		c.Length = l
	}
}

// WithAlgorithm sets the hashing algorithm (e.g., sha1.New, sha256.New, sha512.New).
// Default is sha1.New as per RFC 4226.
func WithAlgorithm(h func() hash.Hash) Option {
	return func(c *Config) {
		c.Algorithm = h
	}
}

// WithCustomBase32 allows setting a custom Base32 alphabet (if not standard).
// This is typically not needed for standard authenticator apps.
func WithCustomBase32(padding string) Option {
	return func(c *Config) {
		// Placeholder for custom base32 implementations if needed in future
	}
}

// NewConfig creates a new Config with default values and applies the given options.
func NewConfig(opts ...Option) *Config {
	c := &Config{
		Length:    DefaultLength,
		Algorithm: sha1.New,
		Encoder:   base32.StdEncoding.WithPadding(base32.NoPadding),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// GenerateCode creates an HOTP code for the given secret and counter.
// The secret should be a base32 encoded string.
// It returns the OTP as a string of digits, padded with leading zeros.
// GenerateCode creates an HOTP code for the given secret and counter.
// The secret should be a base32 encoded string.
// It returns the OTP as a string of digits, padded with leading zeros.
func GenerateCode(secret string, counter uint64, opts ...Option) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	return GenerateCodeFromKey(key, counter, opts...)
}

// GenerateCodeFromKey creates an HOTP code using the raw decoded key bytes.
// This is useful for optimization when the key is already decoded (e.g. in loops).
func GenerateCodeFromKey(key []byte, counter uint64, opts ...Option) (string, error) {
	config := NewConfig(opts...)

	// HMAC Generation
	h := hmac.New(config.Algorithm, key)
	h.Write(utils.Itob(counter))
	mac := h.Sum(nil)

	// Dynamic Truncation
	offset := mac[len(mac)-1] & 0xf
	binCode := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7fffffff

	// Modulo
	mod := int(math.Pow10(config.Length))
	otp := binCode % uint32(mod)

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", config.Length)
	return fmt.Sprintf(format, otp), nil
}

// DecodeSecret handles base32 decoding with loose padding requirements.
// It normalizes the input (uppercase, trim) and adds missing padding if needed.
func DecodeSecret(secret string) ([]byte, error) {
	// Authenticators often don't use padding, so we handle that by ensuring we conform to what the lib expects
	secret = strings.ToUpper(strings.TrimSpace(secret))

	padLen := len(secret) % 8
	if padLen != 0 {
		secret += strings.Repeat("=", 8-padLen)
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 secret: %v", err)
	}
	return key, nil
}

// Validate checks if the provided passcode matches the generated HOTP code
// for the given secret and counter. It returns true if they match.
func Validate(passcode, secret string, counter uint64, opts ...Option) bool {
	code, err := GenerateCode(secret, counter, opts...)
	if err != nil {
		return false
	}
	return utils.ConstantTimeCompare(passcode, code)
}
