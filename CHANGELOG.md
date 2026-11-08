# Changelog

## [2.0.2](https://github.com/fawwazid/go-mfa/compare/v2.0.1...v2.0.2) (2026-11-08)


### Documentation

* document branch and pull request workflow ([3420e7a](https://github.com/fawwazid/go-mfa/commit/3420e7a784b2296176f4c39e081ea29e1346e605))

## [2.0.1](https://github.com/fawwazid/go-mfa/compare/v2.0.0...v2.0.1) (2026-11-01)


### Bug Fixes

* **release:** configure semantic versioning ([#8](https://github.com/fawwazid/go-mfa/issues/8)) ([ad37265](https://github.com/fawwazid/go-mfa/commit/ad37265eb89a6436e81712ede690dd97585c07c7))


### Chores

* configure Google Release Please ([5ca3ace](https://github.com/fawwazid/go-mfa/commit/5ca3acea3beb256f495146bc36e5c11809c80a0b))
* reset Release Please baseline ([b472943](https://github.com/fawwazid/go-mfa/commit/b4729436df997103960e9e45fd250a146c6b5376))


### Security

* bound OTP inputs and random output ([#7](https://github.com/fawwazid/go-mfa/issues/7)) ([dcabe7c](https://github.com/fawwazid/go-mfa/commit/dcabe7c46201989cf452c619521dfec9af920cf8))

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
