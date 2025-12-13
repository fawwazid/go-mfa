// Package totp implements the Time-based One-Time Password algorithm as defined in RFC 6238.
// It supports QR code generation and flexible configuration (algorithm, digits, period).
package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"image"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/fawwazid/go-mfa/hotp"
	"github.com/fawwazid/go-mfa/utils"
)

const (
	DefaultPeriod = 30
	DefaultSkew   = 1 // 1 period before and after
)

// GenerateSecret creates a new random Base32 encoded secret of the given type.
// If sha1 is used, 20 bytes are generated.
// If sha256 is used, 32 bytes are generated.
// If sha512 is used, 64 bytes are generated.
// If algo is nil, it defaults to SHA1 (20 bytes).
func GenerateSecret(algo func() hash.Hash) (string, error) {
	_, size := getAlgoParams(algo)

	bytes, err := utils.GenericRandomBytes(size)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(bytes), nil
}

// Config represents the configuration for TOTP generation.
type Config struct {
	Period    uint64
	Skew      uint
	Time      time.Time
	Algorithm func() hash.Hash
	Length    int
}

// Option is a functional option to configure the TOTP generator.
type Option func(*Config)

// WithPeriod sets the time period in seconds (default: 30s).
func WithPeriod(seconds uint64) Option {
	return func(c *Config) {
		c.Period = seconds
	}
}

// WithSkew sets the validation window size in periods (default: 1).
// E.g., if period=30s and skew=1, tokens are valid for 90s (prev, curr, next).
func WithSkew(periods uint) Option {
	return func(c *Config) {
		c.Skew = periods
	}
}

// WithTime sets a specific time for generation or validation.
// Defaults to time.Now().
func WithTime(t time.Time) Option {
	return func(c *Config) {
		c.Time = t
	}
}

// WithLength sets the length of the generated OTP (e.g., 6 or 8 digits).
// It re-exports the option from the hotp package for convenience.
func WithLength(l int) Option {
	return func(c *Config) {
		c.Length = l
	}
}

// WithAlgorithm sets the HMAC algorithm.
// It re-exports the option from the hotp package for convenience.
func WithAlgorithm(h func() hash.Hash) Option {
	return func(c *Config) {
		c.Algorithm = h
	}
}

// NewConfig creates a new Config with default values and applies the given options.
func NewConfig(opts ...Option) *Config {
	c := &Config{
		Period:    DefaultPeriod,
		Skew:      DefaultSkew,
		Time:      time.Now(),
		Length:    hotp.DefaultLength,
		Algorithm: sha1.New,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// getAlgoParams retrieves the name and key size for the configured hash algorithm.
func getAlgoParams(h func() hash.Hash) (string, int) {
	if h == nil {
		return "SHA1", 20
	}
	ptr := reflect.ValueOf(h).Pointer()
	if ptr == reflect.ValueOf(sha256.New).Pointer() {
		return "SHA256", 32
	}
	if ptr == reflect.ValueOf(sha512.New).Pointer() {
		return "SHA512", 64
	}
	// Default to SHA1
	return "SHA1", 20
}

// GenerateCode creates a TOTP code for the given secret and current time (or configured time).
func GenerateCode(secret string, opts ...Option) (string, error) {
	config := NewConfig(opts...)

	counter := uint64(config.Time.Unix()) / config.Period

	// Delegate to HOTP
	return hotp.GenerateCode(secret, counter,
		hotp.WithLength(config.Length),
		hotp.WithAlgorithm(config.Algorithm))
}

// Validate checks if the passcode is correct for the given secret and current time.
// It accounts for clock skew by checking [current-skew, current+skew] periods.
func Validate(passcode, secret string, opts ...Option) bool {
	config := NewConfig(opts...)

	// Optimization: Decode secret once
	key, err := hotp.DecodeSecret(secret)
	if err != nil {
		return false
	}

	currentCounter := uint64(config.Time.Unix()) / config.Period

	// Check current, then back, then forward
	// Range: [current - skew, current + skew]

	start := currentCounter - uint64(config.Skew)
	end := currentCounter + uint64(config.Skew)

	for i := start; i <= end; i++ {
		code, err := hotp.GenerateCodeFromKey(key, i,
			hotp.WithLength(config.Length),
			hotp.WithAlgorithm(config.Algorithm))
		if err == nil && code == passcode {
			return true
		}
	}

	return false
}

// GenerateURL creates the otpauth:// URI string standard for authenticator apps.
func GenerateURL(account, issuer, secret string, opts ...Option) string {
	config := NewConfig(opts...)
	algoName, _ := getAlgoParams(config.Algorithm)

	v := url.Values{}
	v.Set("secret", strings.TrimSpace(secret))
	v.Set("issuer", issuer)
	v.Set("period", strconv.FormatUint(config.Period, 10))
	v.Set("digits", strconv.Itoa(config.Length))
	v.Set("algorithm", algoName)

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     fmt.Sprintf("/%s:%s", issuer, account),
		RawQuery: v.Encode(),
	}

	return u.String()
}

// GenerateQR creates a QR code image for the TOTP configuration.
// It returns a standard image.Image which can be saved to a file or encoded to PNG.
// The size parameter determines the width and height of the image in pixels.
func GenerateQR(account, issuer, secret string, size int, opts ...Option) (image.Image, error) {
	uri := GenerateURL(account, issuer, secret, opts...)
	return createQR(uri, size)
}

// Enrollment represents the data needed to provision a user's device.
type Enrollment struct {
	Secret string      // The Base32 secret key for manual entry.
	URL    string      // The otpauth:// URL.
	Image  image.Image // The QR code image.
}

// GenerateEnrollment creates a new enrollment bundle including the QR code, URL, and Secret.
// This is an all-in-one helper for setting up a new user.
func GenerateEnrollment(account, issuer, secret string, size int, opts ...Option) (*Enrollment, error) {
	// 1. Generate URL
	urlStr := GenerateURL(account, issuer, secret, opts...)

	// 2. Generate QR Image using helper
	qrCode, err := createQR(urlStr, size)
	if err != nil {
		return nil, err
	}

	return &Enrollment{
		Secret: secret,
		URL:    urlStr,
		Image:  qrCode,
	}, nil
}

// createQR is a helper to generate a scaled QR code from a URI string.
func createQR(uri string, size int) (image.Image, error) {
	qrCode, err := qr.Encode(uri, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}
	qrCode, err = barcode.Scale(qrCode, size, size)
	if err != nil {
		return nil, err
	}
	return qrCode, nil
}
