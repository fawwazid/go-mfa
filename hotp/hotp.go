// Package hotp implements counter-based OTPs using HMAC-SHA256 or HMAC-SHA512.
package hotp

import (
	"crypto"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fawwazid/go-mfa/v2/internal/algorithm"
	"github.com/fawwazid/go-mfa/v2/utils"
)

const (
	DefaultLength   = 6
	MinLength       = 6
	MaxLength       = 10
	MinSecretLength = 14
)

var (
	ErrInvalidLength = errors.New("HOTP length must be between 6 and 10 digits")
	ErrInvalidSecret = errors.New("HOTP secret must contain at least 14 bytes")
)

// Config configures OTP generation with an explicit standard hash identifier.
type Config struct {
	Length    int
	Algorithm crypto.Hash
}

type Option func(*Config)

func WithLength(length int) Option { return func(c *Config) { c.Length = length } }

// WithAlgorithm selects crypto.SHA256 or crypto.SHA512.
func WithAlgorithm(hash crypto.Hash) Option { return func(c *Config) { c.Algorithm = hash } }

// NewConfig defaults to six digits and HMAC-SHA256.
func NewConfig(opts ...Option) *Config {
	c := &Config{Length: DefaultLength, Algorithm: crypto.SHA256}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// GenerateCode accepts only canonical uppercase, unpadded standard Base32.
func GenerateCode(secret string, counter uint64, opts ...Option) (string, error) {
	c := NewConfig(opts...)
	if err := c.validate(); err != nil {
		return "", err
	}
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	return generateCodeFromKey(key, counter, c)
}

// GenerateCodeFromKey generates a code from the raw shared secret.
func GenerateCodeFromKey(key []byte, counter uint64, opts ...Option) (string, error) {
	c := NewConfig(opts...)
	if err := c.validate(); err != nil {
		return "", err
	}
	return generateCodeFromKey(key, counter, c)
}

func generateCodeFromKey(key []byte, counter uint64, c *Config) (string, error) {
	if len(key) < MinSecretLength {
		return "", ErrInvalidSecret
	}
	h := hmac.New(c.Algorithm.New, key)
	h.Write(utils.Itob(counter))
	mac := h.Sum(nil)
	offset := mac[len(mac)-1] & 0xf
	binaryCode := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7fffffff
	modulus := uint64(1)
	for range c.Length {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", c.Length, uint64(binaryCode)%modulus), nil
}

// DecodeSecret rejects alternate casing, padding, whitespace, and noncanonical bits.
func DecodeSecret(secret string) ([]byte, error) {
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := encoder.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid Base32 secret: %w", err)
	}
	if len(key) < MinSecretLength {
		return nil, ErrInvalidSecret
	}
	if encoder.EncodeToString(key) != secret {
		return nil, errors.New("noncanonical Base32 secret")
	}
	return key, nil
}

func (c *Config) validate() error {
	if c.Length < MinLength || c.Length > MaxLength {
		return ErrInvalidLength
	}
	_, _, err := algorithm.Params(c.Algorithm)
	return err
}

// Validate compares a code. Applications must atomically consume accepted counters.
func Validate(passcode, secret string, counter uint64, opts ...Option) bool {
	code, err := GenerateCode(secret, counter, opts...)
	return err == nil && utils.ConstantTimeCompare(passcode, code)
}
