# Go MFA Library

`go-mfa` is a flexible, NIST-compliant Go library for generating and validating One-Time Passwords (OTPs).
It supports:
- **TOTP** (Time-Based One-Time Password, RFC 6238)
- **HOTP** (HMAC-Based One-Time Password, RFC 4226)
- **Generic OTP**: Secure random alphanumeric strings for SMS/Email verification.

## Features

- **Standard Compliant**: Validated against RFC 4226 and RFC 6238 test vectors.
- **Flexible**: Customize algorithm (SHA1, SHA256, SHA512), digit length (6, 8, etc.), and time period.
- **QR Code Generation**: Built-in helper to generate QR codes compatible with Google Authenticator, Microsoft Authenticator, etc.
- **Secure**: Uses `crypto/rand` and constant-time comparisons to prevent timing attacks.

## Installation

```bash
go get github.com/fawwazid/go-mfa
```

## Usage

### 1. Time-Based OTP (TOTP)

Standard usage compatible with most authenticator apps (Google Auth, etc.).

```go
package main

import (
    "fmt"
    "github.com/fawwazid/go-mfa/totp"
)

func main() {
    // Secret key (typically stored in your DB for the user)
    // Must be Base32 encoded.
    secret := "JBSWY3DPEHPK3PXP" 

    // Generate a code for the current time
    code, _ := totp.GenerateCode(secret)
    fmt.Println("Current OTP:", code)

    // Validate a user's input
    valid := totp.Validate(code, secret)
    if valid {
        fmt.Println("Access Granted")
    } else {
        fmt.Println("Invalid Code")
    }
}
```

#### Easy Setup / Enrollment

Directly generate everything needed for a new user setup:
- **Secret Key** (for manual entry)
- **QR Code Image** (for scanning)
- **URL** (raw string)

```go
import "github.com/fawwazid/go-mfa/totp"

// 1. Generate a new random secret
secret, _ := totp.GenerateSecret(nil) // nil = Default SHA1

// 2. Generate Enrollment Bundle
enrollment, _ := totp.GenerateEnrollment("user@example.com", "MyApp", secret, 256)

// 3. User Output
fmt.Println("Manual Entry Code:", enrollment.Secret)
// Save enrollment.Image to file or display in UI
// enrollment.URL contains the raw otpauth URL
```

#### Custom Configuration (NIST / Enterprise defaults)

Use options to configure SHA256/SHA512, custom lengths, or time periods.

```go
import (
    "crypto/sha256"
    "github.com/fawwazid/go-mfa/totp"
)

// Generate 8-digit, SHA256, 15-second period OTP
code, _ := totp.GenerateCode(secret,
    totp.WithAlgorithm(sha256.New),
    totp.WithLength(8),
    totp.WithPeriod(15),
)
```

#### QR Code Generation

Generate a QR code image to show to the user for setup.

```go
import "github.com/fawwazid/go-mfa/totp"
// ...

// Generate a 256x256 QR Code
image, err := totp.GenerateQR("user@example.com", "MyApp", secret, 256)
if err == nil {
    // Save 'image' to file or serve via HTTP
}
```

### 2. HMAC-Based OTP (HOTP)

Event-based OTPs where the counter increments on every login.

```go
import "github.com/fawwazid/go-mfa/hotp"

// Counter must be synchronized between client and server
counter := uint64(5) 

code, _ := hotp.GenerateCode(secret, counter)
valid := hotp.Validate("123456", secret, counter)
```

### 3. Generic Random OTP (SMS / Email)

Generate secure random strings for other verification channels.

```go
import "github.com/fawwazid/go-mfa/otp"

// 6-digit number (Default)
code, _ := otp.Generate() 

// 8-character Alphanumeric
alphaCode, _ := otp.Generate(
    otp.WithLength(8), 
    otp.WithAlphaNumeric(),
)
```

## License

[See License](LICENSE)
