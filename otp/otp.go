// Package otp implements generation and validation of generic, cryptographically secure One-Time Passwords (OTPs).
// It supports numeric, alphabetic, and mixed alphanumeric codes, which is useful for SMS or Email verification.
package otp

import (
	"errors"
	"math"
	"unicode/utf8"

	"github.com/fawwazid/go-mfa/v2/utils"
)

// Default settings for OTP generation.
const (
	DefaultLength = 6
	Digits        = "0123456789"
	Letters       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	AlphaNumeric  = Digits + Letters
)

// Config represents the configuration key-values for OTP generation.
type Config struct {
	Length  int
	Charset string
}

// Option is a functional option to configure the OTP generator.
type Option func(*Config)

// WithLength sets the length of the OTP.
func WithLength(l int) Option {
	return func(c *Config) {
		c.Length = l
	}
}

// WithCharset sets a custom charset for the OTP.
func WithCharset(s string) Option {
	return func(c *Config) {
		c.Charset = s
	}
}

// WithDigits sets the charset to numeric digits only (0-9).
func WithDigits() Option {
	return func(c *Config) {
		c.Charset = Digits
	}
}

// WithLetters sets the charset to letters only (a-z, A-Z).
func WithLetters() Option {
	return func(c *Config) {
		c.Charset = Letters
	}
}

// WithAlphaNumeric sets the charset to alphanumeric characters (0-9, a-z, A-Z).
func WithAlphaNumeric() Option {
	return func(c *Config) {
		c.Charset = AlphaNumeric
	}
}

// NewConfig creates a new Config with default values (Length: 6, Charset: Digits)
// and applies the given options.
func NewConfig(opts ...Option) *Config {
	c := &Config{
		Length:  DefaultLength,
		Charset: Digits,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// Generate generates a cryptographically secure random OTP string based on the provided options.
// Defaults to 6 digits if no options are provided.
func Generate(opts ...Option) (string, error) {
	config := NewConfig(opts...)
	if config.Length < 1 || config.Length > 1024 || len(config.Charset) > 4096 || !utf8.ValidString(config.Charset) {
		return "", errors.New("invalid OTP length or charset")
	}
	unique := make(map[rune]bool)
	for _, r := range config.Charset {
		if unique[r] {
			return "", errors.New("OTP charset must not contain duplicate characters")
		}
		unique[r] = true
	}
	// SP 800-63B-4 requires at least six decimal digits or equivalent entropy.
	if len(unique) < 2 || float64(config.Length)*math.Log2(float64(len(unique))) < math.Log2(1_000_000) {
		return "", errors.New("OTP must provide at least six decimal digits of entropy")
	}
	return utils.CryptoRandomString(config.Length, config.Charset)
}

// Validate compares the input OTP with the expected OTP in constant time.
// It returns true if they match, false otherwise.
func Validate(input, expected string) bool {
	if expected == "" {
		return false
	}
	return utils.ConstantTimeCompare(input, expected)
}
