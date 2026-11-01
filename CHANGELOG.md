# Changelog

## [3.0.0](https://github.com/fawwazid/go-mfa/compare/v2.0.0...v3.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* prepare v2 security refactor ([#5](https://github.com/fawwazid/go-mfa/issues/5))

### Features

* implement NIST compliant MFA library ([#1](https://github.com/fawwazid/go-mfa/issues/1)) ([2aeeec3](https://github.com/fawwazid/go-mfa/commit/2aeeec3101f07a0cd659937f769c17f7e523111f))
* prepare v2 security refactor ([#5](https://github.com/fawwazid/go-mfa/issues/5)) ([b9edf20](https://github.com/fawwazid/go-mfa/commit/b9edf20f89e01ef1c097824940515104e11d9a78))


### Bug Fixes

* harden-mfa-generation-and-validation ([#3](https://github.com/fawwazid/go-mfa/issues/3)) ([a6cbd6d](https://github.com/fawwazid/go-mfa/commit/a6cbd6d9145e73342ff20de3a69e2ce017a0b5f8))

## v2.0.0 — 2026-10-24

Use SHA-256/SHA-512 OTPs and canonical enrollment data.

### Breaking changes

- Module path is now `github.com/fawwazid/go-mfa/v2`. Update imports and use Go 1.27.3 or later.
- Remove SHA-1, DefaultAlgo, WithCustomBase32, custom encoder options, and permissive secret normalization.
- WithAlgorithm and GenerateSecret now accept crypto.Hash, limited to crypto.SHA256 and crypto.SHA512.
- Replace GenerateURLChecked and the string-only URL wrapper with GenerateURL returning (string, error).
- Require at least six digits, 14 decoded secret bytes, and canonical uppercase unpadded Base32.

### Security and maintenance

- Default to SHA-256; share algorithm selection without reflection.
- Bound random OTP output and charset entropy; reject empty expected codes.
- Cover RFC 6238 SHA-256/SHA-512 vectors and the maximum supported Unix timestamp.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-mfa/v2@v2.0.0
```

## v1.0.1 — 2026-10-15

- Harden MFA code generation and validation.

## v1.0.0 — 2025-12-13

- Initial release of the NIST-guided MFA library.
