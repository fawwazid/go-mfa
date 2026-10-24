# go-mfa

Install: `go get github.com/fawwazid/go-mfa/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

HOTP/TOTP with HMAC-SHA256 or HMAC-SHA512, canonical Base32 enrollment, QR
generation, and secure random OTP helpers. Requires Go 1.27.3.

## Usage

```go
package main

import (
 "crypto"
 "fmt"
 "log"
 "github.com/fawwazid/go-mfa/v2/totp"
)

func main() {
 secret, err := totp.GenerateSecret(crypto.SHA256)
 if err != nil { log.Fatal(err) }
 enrollment, err := totp.GenerateEnrollment("user@example.com", "App", secret, 256)
 if err != nil { log.Fatal(err) }
 code, err := totp.GenerateCode(secret)
 if err != nil { log.Fatal(err) }
 fmt.Println(enrollment.URL, totp.Validate(code, secret))
}
```

Enrollment secrets and URIs are sensitive. Protect them in storage and during
provisioning. This example prints the URI only to demonstrate the API.

## Algorithms and configuration

The default is SHA-256, six digits, a 30-second TOTP period, and skew one.
`WithAlgorithm(crypto.SHA512)` selects SHA-512; use the same choice for secret
generation, enrollment, and validation. There is no algorithm auto-detection.

HOTP/TOTP secrets must be uppercase, unpadded standard Base32 and decode to at
least 14 bytes. Codes require 6–10 digits. `GenerateSecret` creates 32 bytes for
SHA-256 or 64 bytes for SHA-512.

- HOTP: `GenerateCode`, `GenerateCodeFromKey`, `DecodeSecret`, `Validate`.
- TOTP: `GenerateSecret`, `GenerateCode`, `Validate`, `GenerateURL`,
  `GenerateQR`, `GenerateEnrollment`.
- `GenerateURL` returns `(string, error)`; invalid configuration is never hidden.
- Random OTP: `otp.Generate()`, `WithLength`, and the charset options.
  Charsets must have unique characters and at least six decimal digits'
  equivalent output entropy. `otp.Validate` rejects empty expected codes.

## Breaking changes

SHA-1, `DefaultAlgo`, `WithCustomBase32`, custom encoder options, and permissive
secret normalization have been removed. `WithAlgorithm` and `GenerateSecret`
now take `crypto.Hash`, not hash constructor functions or nil.
`GenerateURLChecked` and the string-only URL wrapper have been replaced by the
single error-returning `GenerateURL` API. Existing SHA-1 or weak-secret
enrollments must be replaced before using this API.

## Application requirements

Atomically consume accepted HOTP counters and TOTP time steps. Enforce expiry,
per-account attempt limits, and protected enrollment. These helpers provide no
persistent replay or rate-limit store. OTPs are not phishing-resistant.
NIST SP 800-63B-4 does not permit email as an out-of-band authenticator; SMS is
restricted. Email address verification is a separate use case.

See [SECURITY.md](SECURITY.md) for FIPS builds and scope.
Run `go test ./...` and `go vet ./...`. License: [MIT](LICENSE).
