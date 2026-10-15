// Package hotp implements the HMAC-based One-Time Password algorithm as defined in RFC 4226.
package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/fawwazid/go-mfa/utils"
)

// Default settings for HOTP.
const (
	DefaultLength = 6
	DefaultAlgo   = "sha1" // Deprecated: use sha1.New when configuring the algorithm.
	MinLength     = 1
	MaxLength     = 10
)

var (
	ErrInvalidLength    = errors.New("HOTP length must be between 1 and 10 digits")
	ErrInvalidAlgorithm = errors.New("HOTP algorithm must not be nil")
	ErrInvalidHash      = errors.New("HOTP algorithm returned a hash that is too short")
	ErrInvalidEncoder   = errors.New("HOTP Base32 encoder must not be nil")
	ErrInvalidSecret    = errors.New("HOTP secret must not be empty")
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

// WithEncoder sets the Base32 encoding used to decode secrets.
func WithEncoder(encoder *base32.Encoding) Option {
	return func(c *Config) {
		c.Encoder = encoder
	}
}

// WithCustomBase32 is retained for source compatibility.
// Deprecated: use WithEncoder with an explicit base32.Encoding.
func WithCustomBase32(_ string) Option {
	return func(*Config) {}
}

// NewConfig creates a new Config with default values and applies the given options.
func NewConfig(opts ...Option) *Config {
	c := &Config{
		Length:    DefaultLength,
		Algorithm: sha1.New,
		Encoder:   base32.StdEncoding.WithPadding(base32.NoPadding),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// GenerateCode creates an HOTP code for the given secret and counter.
// The secret should be a base32 encoded string.
// It returns the OTP as a string of digits, padded with leading zeros.
func GenerateCode(secret string, counter uint64, opts ...Option) (string, error) {
	config := NewConfig(opts...)
	if err := config.validate(); err != nil {
		return "", err
	}
	key, err := decodeSecret(secret, config.Encoder)
	if err != nil {
		return "", err
	}
	return generateCodeFromKey(key, counter, config)
}

// GenerateCodeFromKey creates an HOTP code using the raw decoded key bytes.
// This is useful for optimization when the key is already decoded (e.g. in loops).
func GenerateCodeFromKey(key []byte, counter uint64, opts ...Option) (string, error) {
	config := NewConfig(opts...)
	if err := config.validate(); err != nil {
		return "", err
	}
	return generateCodeFromKey(key, counter, config)
}

func generateCodeFromKey(key []byte, counter uint64, config *Config) (string, error) {
	if len(key) == 0 {
		return "", ErrInvalidSecret
	}

	// HMAC Generation
	h := hmac.New(config.Algorithm, key)
	h.Write(utils.Itob(counter))
	mac := h.Sum(nil)

	// Dynamic Truncation
	offset := mac[len(mac)-1] & 0xf
	if int(offset)+4 > len(mac) {
		return "", ErrInvalidHash
	}
	binCode := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7fffffff

	// Modulo
	mod := uint64(1)
	for range config.Length {
		mod *= 10
	}
	otp := uint64(binCode) % mod

	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", config.Length)
	return fmt.Sprintf(format, otp), nil
}

// DecodeSecret handles Base32 decoding case-insensitively and accepts optional padding.
func DecodeSecret(secret string) ([]byte, error) {
	return decodeSecret(secret, base32.StdEncoding.WithPadding(base32.NoPadding))
}

func decodeSecret(secret string, encoder *base32.Encoding) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	candidates := []string{
		secret,
		strings.TrimRight(secret, "="),
		strings.ToUpper(secret),
		strings.TrimRight(strings.ToUpper(secret), "="),
	}
	var decodeErr error
	for _, candidate := range candidates {
		key, err := encoder.DecodeString(candidate)
		if err == nil {
			if len(key) == 0 {
				return nil, errors.New("invalid base32 secret: secret must not be empty")
			}
			return key, nil
		}
		decodeErr = err
	}
	return nil, fmt.Errorf("invalid base32 secret: %w", decodeErr)
}

func (c *Config) validate() error {
	if c.Length < MinLength || c.Length > MaxLength {
		return ErrInvalidLength
	}
	if c.Algorithm == nil {
		return ErrInvalidAlgorithm
	}
	sample := c.Algorithm()
	if sample == nil || sample.Size() < 20 || sample.BlockSize() < 1 {
		return ErrInvalidHash
	}
	if c.Encoder == nil {
		return ErrInvalidEncoder
	}
	return nil
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
