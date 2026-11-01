# Agent instructions

This repository is the `go-mfa` Go module. Keep changes within this module
unless the task explicitly spans other repositories. Preserve existing user
changes. Do not create or edit changelogs; Release Please generates them.

## Security and API

- HOTP/TOTP support SHA-256 and SHA-512 only; do not restore SHA-1 or
  permissive secret normalization.
- Preserve canonical Base32, secret, code, skew, QR, label, and random-input
  bounds.
- Bound `ConstantTimeCompare` inputs before converting strings to byte slices.
- Keep OTP verification stateless. Document that applications must atomically
  consume accepted codes and provide expiry, replay prevention, rate limiting,
  protected secret storage, and secure enrollment.
- OTPs are not phishing-resistant. Avoid claiming this package establishes an
  authentication assurance level or is independently FIPS-certified.

## Development

- Workspace mail invariant: `go-mail` caps messages at 1,000 recipients, 100
  attachments, and 25 MiB; untrusted attachment bytes use its checked API.
- Workspace MFA invariant: `ConstantTimeCompare` rejects strings longer than
  4,096 UTF-8 bytes before allocating byte slices.

- Target the Go version in `go.mod`; format Go changes with `gofmt`.
- Keep README and security documentation aligned with the API and application
  responsibilities.
- Remove only clearly unused internal code; preserve exported APIs unless a
  breaking change is explicitly requested.
- Add or update regression tests for every code change and run the affected
  module's complete test suite before finishing. Run `go vet ./...` as well.
- Review OTP changes against applicable RFC 4226/6238, NIST SP 800-63B, and
  FIPS guidance. Preserve replay, expiry, rate-limit, and enrollment caveats.
- For every workspace code, test, or security-policy change, review and update
  all eight module-level `AGENTS.md` files in the same change set so their
  constraints and test-coverage notes stay aligned. Keep updates concise; this
  is not a changelog.

## Test coverage notes

- HOTP tests cover the maximum accepted raw secret size.
- TOTP tests cover escaped label path separators and the account-label bound.
- Utility tests cover random string and random byte limits plus duplicate
  charset runes and oversized comparison inputs.
