# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- GitHub Actions CI for stable Rust, Rust 1.85 MSRV, and embedded `no_std`.
- Automated crates.io publishing from matching GitHub release tags.
- Supply-chain policy checks and Dependabot configuration.
- Criterion benchmarks and resource-bounded mutation testing.

## 0.1.0 - 2026-07-30

### Added

- Strict RFC 4226 HOTP generation and bounded look-ahead verification.
- Strict RFC 6238 TOTP with SHA-1, SHA-256, and SHA-512.
- Six-, seven-, and eight-digit codes with strict ASCII parsing.
- Constant-time code comparison and zeroized transient cryptographic state.
- Borrowed secrets with a mandatory 128-bit minimum.
- `no_std` operation, checked 64-bit arithmetic, and Rust 1.85 MSRV.
- Complete RFC vector, boundary, API contract, and documentation tests.

[Unreleased]: https://github.com/copyleftdev/totp-rfc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/copyleftdev/totp-rfc/releases/tag/v0.1.0
