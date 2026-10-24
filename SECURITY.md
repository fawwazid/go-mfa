# Security policy

## Current contract

HOTP and TOTP support only crypto.SHA256 and crypto.SHA512; SHA-256 is the
default in every runtime mode. SHA-1 and custom hash/encoder constructors are
absent. Secrets must be canonical uppercase, unpadded Base32 with at least 14
decoded bytes. Generated secrets contain 32 or 64 bytes. Codes require 6–10
digits. Random OTPs require at least six decimal digits' equivalent entropy,
unique charset characters, and bounded output length. Empty expected codes
never match. GenerateURL returns errors rather than suppressing them.

Applications must atomically consume accepted HOTP counters and TOTP steps,
enforce expiry and per-account rate limits, protect secret storage, and secure
enrollment. There is no persistence layer in this library. OTPs are not
phishing-resistant. SP 800-63B-4 does not permit email for out-of-band
authentication; SMS is restricted. Email address verification is a separate
use case. These helpers do not establish an authentication assurance level.

This release removes source and behavior compatibility with the APIs listed
under Breaking changes in README.md. Unsupported inputs are rejected.
Applications must replace unsupported records or enrollments before upgrading;
this library does not provide conversion or permissive verification helpers.

## FIPS deployment

This library is not independently FIPS 140-3 certified. Deployment compliance
depends on the validated Go module, its approved operating environment,
security policy, and application controls. A library cannot enable FIPS mode
for its caller.

The baseline is Go 1.27.3. The frozen Go module v1.0.0 corresponds to
[CMVP certificate 5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247),
checked active on 2026-10-24. Review certificate status and operating-environment
coverage before deployment. A consuming application can build with
GOFIPS140=v1.0.0 and must not override it with fips140=off.
The strict only setting below is an assessment aid, not a production setting.

## Verification

Ordinary checks:

```sh
go mod verify
go vet ./...
go test ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Dedicated policy tests with the frozen module:

```sh
GOFIPS140=v1.0.0 GODEBUG=fips140=on go test -count=1 -run FIPS ./...
GOFIPS140=v1.0.0 GODEBUG=fips140=only go test -count=1 -run FIPS ./...
```

In PowerShell, set the variables with
`$env:GOFIPS140 = 'v1.0.0'` and `$env:GODEBUG = 'fips140=on'` or
`'fips140=only'`, then run the go test command. Restore the original environment
after checking.

CI is configured for Windows and Linux, including Linux race detection.
Local validation is limited to the platform and commands actually executed;
see the workspace SECURITY_REVIEW.md for the recorded results.

## References

- [Go FIPS documentation](https://go.dev/doc/security/fips140)
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
