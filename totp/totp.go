// Package totp implements the Time-based One-Time Password algorithm as defined in RFC 6238.
// It supports QR code generation and flexible configuration (algorithm, digits, period).
package totp

import (
	"crypto"
	"encoding/base32"
	"errors"
	"fmt"
	"image"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/fawwazid/go-mfa/v2/hotp"
	"github.com/fawwazid/go-mfa/v2/internal/algorithm"
	"github.com/fawwazid/go-mfa/v2/utils"
)

const (
	DefaultPeriod = 30
	DefaultSkew   = 1 // 1 period before and after
	MaxSkew       = 10
	MaxQRSize     = 4096
)

var (
	ErrInvalidPeriod = errors.New("TOTP period must be greater than zero")
	ErrInvalidSkew   = errors.New("TOTP skew must not exceed 10 periods")
	ErrInvalidTime   = errors.New("TOTP time must not be before the Unix epoch")
	ErrInvalidQRSize = errors.New("TOTP QR size must be between 1 and 4096 pixels")
	ErrInvalidLabel  = errors.New("TOTP account and issuer must be non-empty and must not contain colons")
)

// GenerateSecret creates a canonical Base32 secret for crypto.SHA256 or crypto.SHA512.
func GenerateSecret(hash crypto.Hash) (string, error) {
	_, size, err := algorithm.Params(hash)
	if err != nil {
		return "", err
	}

	bytes, err := utils.GenericRandomBytes(size)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

// Config represents the configuration for TOTP generation.
type Config struct {
	Period    uint64
	Skew      uint
	Time      time.Time
	Algorithm crypto.Hash
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
func WithLength(l int) Option {
	return func(c *Config) {
		c.Length = l
	}
}

// WithAlgorithm selects crypto.SHA256 or crypto.SHA512.
func WithAlgorithm(h crypto.Hash) Option {
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
		Algorithm: crypto.SHA256,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// GenerateCode creates a TOTP code for the given secret and current time (or configured time).
func GenerateCode(secret string, opts ...Option) (string, error) {
	config := NewConfig(opts...)
	if err := config.validateStatic(); err != nil {
		return "", err
	}
	if config.Time.Unix() < 0 {
		return "", ErrInvalidTime
	}

	counter := uint64(config.Time.Unix()) / config.Period

	return hotp.GenerateCode(secret, counter,
		hotp.WithLength(config.Length),
		hotp.WithAlgorithm(config.Algorithm))
}

// Validate checks if the passcode is correct for the given secret and current time.
// It accounts for clock skew by checking [current-skew, current+skew] periods.
func Validate(passcode, secret string, opts ...Option) bool {
	config := NewConfig(opts...)
	if err := config.validateStatic(); err != nil || config.Time.Unix() < 0 {
		return false
	}

	key, err := hotp.DecodeSecret(secret)
	if err != nil {
		return false
	}

	currentCounter := uint64(config.Time.Unix()) / config.Period

	var start uint64
	if currentCounter >= uint64(config.Skew) {
		start = currentCounter - uint64(config.Skew)
	} else {
		start = 0
	}
	end := currentCounter + uint64(config.Skew)

	for i := start; i <= end; i++ {
		code, err := hotp.GenerateCodeFromKey(key, i,
			hotp.WithLength(config.Length),
			hotp.WithAlgorithm(config.Algorithm))
		if err == nil && utils.ConstantTimeCompare(code, passcode) {
			return true
		}
	}

	return false
}

// GenerateURL creates an otpauth URI and reports invalid configuration.
func GenerateURL(account, issuer, secret string, opts ...Option) (string, error) {
	config := NewConfig(opts...)
	if err := config.validateStatic(); err != nil {
		return "", err
	}
	algoName, _, err := algorithm.Params(config.Algorithm)
	if err != nil {
		return "", err
	}
	if account == "" || issuer == "" || strings.Contains(account, ":") || strings.Contains(issuer, ":") {
		return "", ErrInvalidLabel
	}
	if _, err := hotp.DecodeSecret(secret); err != nil {
		return "", err
	}

	v := url.Values{}
	v.Set("secret", secret)
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

	return u.String(), nil
}

// GenerateQR creates a QR code image for the TOTP configuration.
// It returns a standard image.Image which can be saved to a file or encoded to PNG.
// The size parameter determines the width and height of the image in pixels.
func GenerateQR(account, issuer, secret string, size int, opts ...Option) (image.Image, error) {
	uri, err := GenerateURL(account, issuer, secret, opts...)
	if err != nil {
		return nil, err
	}
	return createQR(uri, size)
}

// Enrollment represents the data needed to provision a user's device.
type Enrollment struct {
	Secret string      // The Base32 secret key for manual entry.
	URL    string      // The otpauth:// URL.
	Image  image.Image // The QR code image.
}

// GenerateEnrollment creates a new enrollment bundle including the QR code, URL, and Secret.
func GenerateEnrollment(account, issuer, secret string, size int, opts ...Option) (*Enrollment, error) {
	urlStr, err := GenerateURL(account, issuer, secret, opts...)
	if err != nil {
		return nil, err
	}

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

func createQR(uri string, size int) (image.Image, error) {
	if size < 1 || size > MaxQRSize {
		return nil, ErrInvalidQRSize
	}
	qrCode, err := qr.Encode(uri, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}
	return barcode.Scale(qrCode, size, size)
}

func (c *Config) validateStatic() error {
	if c.Skew > MaxSkew {
		return ErrInvalidSkew
	}
	if c.Period == 0 {
		return ErrInvalidPeriod
	}
	if c.Length < hotp.MinLength || c.Length > hotp.MaxLength {
		return hotp.ErrInvalidLength
	}
	_, _, err := algorithm.Params(c.Algorithm)
	return err
}
