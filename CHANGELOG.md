# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.1.2 - 2026-07-30

### Changed

- Positioned the crate as a security-hardened, allocation-free `no_std`
  HOTP/TOTP verification core for Rust.
- Clarified the boundary between the auditable OTP primitive layer and
  provisioning, QR, clock, database, and secret-generation concerns.
- Improved crates.io search metadata for `constant-time` and `no-std` users.

## 0.1.1 - 2026-07-30

### Added

- Resource-bounded adversarial tests for hostile syntax, Unicode confusables,
  protocol confusion, replay assumptions, independent HMAC oracle sweeps,
  panic resistance, decimal-code collision semantics, and arithmetic
  boundaries.
- Opt-in dudect timing-leakage probes for code values, mismatch position,
  secret contents across all three RFC hash algorithms, counter contents,
  validation-window match position, and harness calibration.
- Calibrated Valgrind secret-taint analysis, three-pass machine-readable timing
  evidence, and a bounded release-assurance runner.
- GitHub Actions CI for stable Rust, Rust 1.85 MSRV, and embedded `no_std`.
- Automated crates.io publishing from matching GitHub release tags.
- Supply-chain policy checks and Dependabot configuration.
- Criterion benchmarks and resource-bounded mutation testing.

### Changed

- Dynamic truncation now reads all 16 RFC-permitted windows and uses masked
  selection instead of a secret-derived memory address.
- HOTP and TOTP window searches use masked first-match selection so match
  position does not affect control flow.

## 0.1.0 - 2026-07-30

### Added

- Strict RFC 4226 HOTP generation and bounded look-ahead verification.
- Strict RFC 6238 TOTP with SHA-1, SHA-256, and SHA-512.
- Six-, seven-, and eight-digit codes with strict ASCII parsing.
- Constant-time code comparison and zeroized transient cryptographic state.
- Borrowed secrets with a mandatory 128-bit minimum.
- `no_std` operation, checked 64-bit arithmetic, and Rust 1.85 MSRV.
- Complete RFC vector, boundary, API contract, and documentation tests.

[Unreleased]: https://github.com/copyleftdev/totp-rfc/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/copyleftdev/totp-rfc/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/copyleftdev/totp-rfc/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/copyleftdev/totp-rfc/releases/tag/v0.1.0
