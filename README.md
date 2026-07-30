# totp-rfc

[![Crates.io](https://img.shields.io/crates/v/totp-rfc.svg)](https://crates.io/crates/totp-rfc)
[![Documentation](https://docs.rs/totp-rfc/badge.svg)](https://docs.rs/totp-rfc)
[![CI](https://github.com/copyleftdev/totp-rfc/actions/workflows/ci.yml/badge.svg)](https://github.com/copyleftdev/totp-rfc/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](#minimum-supported-rust-version)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Core-only](https://img.shields.io/badge/no__std-supported-success.svg)](#no_std)

Security-hardened, allocation-free, `no_std` HOTP and TOTP primitives for
Rust.

`totp-rfc` is a compact Rust authentication library implementing the HMAC-based
one-time password algorithm from
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) and the time-based one-time
password algorithm from [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
It is designed for embedded, server, and security-sensitive 2FA and MFA systems
that need a small, auditable verification core instead of provisioning,
QR-code, or storage abstractions.

## Why totp-rfc?

- Exact RFC 4226 HOTP and RFC 6238 TOTP behavior
- HMAC-SHA-1, HMAC-SHA-256, and HMAC-SHA-512 through `RustCrypto`
- Six-, seven-, and eight-digit decimal one-time passwords
- Mandatory 128-bit minimum secret length
- Strict ASCII input parsing with preserved leading zeroes
- Constant-address dynamic truncation across every RFC-defined digest offset
- Constant-time comparison and first-match selection for well-formed codes
- Checked 64-bit counters and timestamps beyond the year 2038
- Bounded HOTP resynchronization and TOTP clock-drift windows
- Borrowed secrets and zeroized transient HMAC/hash state
- `no_std`, no allocation, and no unsafe Rust

The [RFC compliance matrix](docs/compliance.md) maps each protocol requirement
to its implementation and test evidence.

## Deliberately a primitive layer

Choose `totp-rfc` when the trusted OTP core should remain compact, portable,
allocation-free, and independently testable. It exposes explicit timestamps,
counters, validation windows, drift, and next-counter state so the surrounding
authentication service can enforce its own replay and throttling policy.

Base32, `otpauth://` provisioning, QR generation, random-secret generation,
database access, and system-clock policy remain outside the crate. Applications
that want an all-in-one enrollment toolkit can compose those concerns above
`totp-rfc` without adding them to the cryptographic verification boundary.

## Installation

Add the crate with Cargo:

```console
cargo add totp-rfc
```

Or add it directly to `Cargo.toml`:

```toml
[dependencies]
totp-rfc = "0.1"
```

## TOTP example

The default configuration is HMAC-SHA-1, six digits, a 30-second period, and
Unix epoch `T0 = 0`:

```rust
use totp_rfc::{Secret, Totp, ValidationWindow};

let secret = Secret::new(b"12345678901234567890").unwrap();
let totp = Totp::default();

let code = totp.generate(&secret, 59).unwrap();
assert_eq!(code.to_string(), "287082");

let matched = totp
    .verify_window(
        &secret,
        59,
        ValidationWindow::RFC_RECOMMENDED,
        "287082",
    )
    .unwrap()
    .unwrap();

assert_eq!(matched.counter(), 1);
assert_eq!(matched.drift(), 0);
```

For eight-digit HMAC-SHA-256 TOTP:

```rust
use totp_rfc::{Algorithm, Digits, Secret, Totp};

let secret = Secret::new(b"12345678901234567890123456789012").unwrap();
let totp = Totp::new(Algorithm::Sha256, Digits::EIGHT, 30, 0).unwrap();

assert_eq!(
    totp.generate(&secret, 59).unwrap().to_string(),
    "46119246"
);
```

## HOTP example

```rust
use totp_rfc::{Hotp, Secret};

let secret = Secret::new(b"12345678901234567890").unwrap();
let hotp = Hotp::default();

assert_eq!(hotp.generate(&secret, 0).to_string(), "755224");

let matched = hotp
    .verify_window(&secret, 0, 10, "287922")
    .unwrap()
    .unwrap();

assert_eq!(matched.counter(), 6);
assert_eq!(matched.next_counter(), Some(7));
```

## Supported protocol parameters

| Primitive | Algorithms | Digits | Moving factor |
|---|---|---:|---|
| HOTP | HMAC-SHA-1 | 6, 7, 8 | 64-bit event counter |
| TOTP | HMAC-SHA-1, SHA-256, SHA-512 | 6, 7, 8 | 64-bit Unix time-step counter |

All counters are encoded as unsigned, eight-byte, big-endian values. TOTP uses
`T = floor((timestamp - T0) / period)` and rejects timestamps before `T0`.

## Security boundary

This crate calculates and matches one-time passwords. A production validation
service must still:

- generate a unique cryptographically random secret for every credential;
- encrypt secrets at rest and restrict access to decrypted key material;
- throttle failures across sessions and distributed server instances;
- atomically persist `HotpMatch::next_counter()` after HOTP success;
- record accepted TOTP counters and reject reuse after successful validation;
- use secure transport and an independent authentication factor;
- keep resynchronization and clock-drift windows as small as possible.

The `Secret` wrapper borrows key material and does not own or retain it.
`RustCrypto`'s zeroization support clears transient HMAC and hash state on drop.
Long-term storage encryption, memory locking, and caller-owned key zeroization
remain application responsibilities.

Constant-time equality protects comparisons of well-formed code values. It is
not a claim that the complete generation or verification path is
side-channel-free on every compiler, target, cryptographic backend, or CPU.
Use the repository's statistical timing lab on deployment-representative
hardware for changes affecting those paths.

Use at least 20 random bytes for SHA-1, 32 for SHA-256, or 64 for SHA-512. The
API enforces RFC 4226's mandatory minimum of 16 bytes.

## `no_std`

Disable default features for embedded and core-only environments:

```toml
[dependencies]
totp-rfc = { version = "0.1", default-features = false }
```

The default `std` feature only adds implementations of `std::error::Error`.
Cryptographic calculation requires neither allocation nor access to the system
clock.

## Verification quality

The repository tests:

- every RFC 4226 Appendix D HOTP vector;
- all SHA-1, SHA-256, and SHA-512 vectors from RFC 6238 Appendix B;
- a bounded [attacker-oriented suite](docs/adversarial-testing.md) covering
  hostile syntax, Unicode confusables, protocol confusion, replay assumptions,
  independent HMAC oracle sweeps, panic resistance, and arithmetic attacks;
- a calibrated [security assurance case](docs/security-assurance.md) combining
  secret-taint analysis and repeated statistical timing evidence;
- time, counter, parsing, overflow, drift, and replay-state boundaries;
- default-feature and `no_std` configurations;
- the declared Rust 1.85 minimum version;
- every viable mutation generated across the library.

Run the focused attacker suite:

```console
./scripts/adversarial-test.sh
```

Run the bounded dudect timing-leakage laboratory:

```console
./scripts/timing-test.sh
```

Run the complete bounded release-assurance bundle:

```console
TIMING_CPU=3 ./scripts/assurance-test.sh
```

Run the resource-bounded mutation sweep:

```console
./scripts/mutation-test.sh
```

Run the Criterion primitive benchmarks:

```console
nice -n 10 cargo bench --bench primitives --offline -j 1
```

These suites deliberately limit concurrency and execution time.

## Minimum supported Rust version

The MSRV is Rust 1.85.0 and is checked in CI. An MSRV increase is treated as a
user-visible compatibility change and will be documented in the changelog.

## Project scope

Base32 encoding, `otpauth://` URIs, QR codes, random-secret generation, system
clock access, databases, distributed replay locks, and login throttling belong
in provisioning or service layers. Keeping those concerns outside this crate
preserves a compact, portable, and auditable RFC primitive layer.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
submitting changes. Security reports must follow [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE.md).
