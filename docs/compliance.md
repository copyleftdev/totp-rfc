# RFC compliance matrix

This document maps normative HOTP/TOTP behavior to code and tests. “Caller”
items require application state or provisioning and are intentionally not
claimed as properties of a stateless calculation library.

## RFC 4226

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| Counter-based moving factor | `Hotp::generate` takes a `u64` counter | HOTP Appendix D vectors |
| Counter encoded as 8 bytes, high-order byte first | `counter.to_be_bytes()` | HOTP Appendix D vectors and the `u64::MAX` boundary test |
| HMAC-SHA-1 | HOTP has no algorithm parameter and uses `Hmac<Sha1>` | HOTP Appendix D vectors |
| Dynamic truncation | Low nibble of the last digest byte selects four bytes; the high bit is masked | HOTP Appendix D vectors |
| Decimal reduction | 31-bit value reduced modulo `10^Digit` | Six- and eight-digit RFC vectors |
| At least 6 digits; support 6, 7, and 8 | `Digits` is constructible only for 6 through 8 | Parameter-validation test |
| Shared secret at least 128 bits | `Secret::new` rejects fewer than 16 bytes | Secret boundary test |
| Bounded counter resynchronization | `Hotp::verify_window` takes a bounded `u16` look-ahead and returns the matched/next counters | HOTP window and exhaustion tests |
| Increment server counter after success | Caller must atomically store `HotpMatch::next_counter()` | API documentation |
| Throttle unsuccessful validation attempts | Caller policy and persistent state | Security-boundary documentation |
| Unique, securely stored secret per token | Caller provisioning and key store | Security-boundary documentation |

## RFC 6238

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| TOTP uses HOTP with a time-derived counter | `Totp::counter_at` feeds the same truncation construction | RFC 6238 Appendix B vectors |
| `T = floor((UnixTime - T0) / X)` | Checked unsigned subtraction followed by integer division | Custom epoch/floor boundary test |
| Default `X = 30`, `T0 = 0` | `Totp::DEFAULT_PERIOD` and `Totp::default()` | Default-configuration tests and RFC vectors |
| Prover and verifier use identical system parameters | Immutable `Totp` value contains algorithm, digits, period, and epoch | Constructor/accessor API |
| Time values beyond 32 bits | Timestamp and counter are `u64` | Beyond-2038 test and the 20,000,000,000-second RFC vectors |
| HMAC-SHA-1, SHA-256, and SHA-512 | `Algorithm` exposes exactly those RFC algorithms | All 18 Appendix B vectors |
| Bounded past/future clock-drift validation | `ValidationWindow` is bounded by `u16`; successful validation returns signed drift | Drift and counter-boundary tests |
| At most one past step for ordinary network delay | `ValidationWindow::RFC_RECOMMENDED` is `(past=1, future=0)` | Constant definition |
| Reject reuse after successful validation | Caller records `TotpMatch::counter()` per credential and rejects an already-used step | API and security-boundary documentation |
| Unique, random, protected key | Caller provisioning and key store; recommended sizes exposed by `Algorithm::recommended_key_len` | API documentation |

## Additional strictness

- Candidate codes must contain exactly the configured number of ASCII decimal
  digits. Whitespace, signs, Unicode numerals, and omitted leading zeroes are
  rejected.
- Well-formed code values compare through `subtle` constant-time equality,
  including `Code`'s `PartialEq` implementation.
- Window searches evaluate every representable counter in the requested
  window, even after a match; counter arithmetic never wraps.
- RustCrypto's zeroization features clear transient HMAC and hash state on
  drop; the caller retains responsibility for long-term key storage.
- The crate forbids unsafe Rust, denies missing public documentation, supports
  `no_std`, and tests both feature configurations.

## Deliberate non-goals

Base32 encoding, `otpauth://` URIs, QR codes, current-clock acquisition,
random-key generation, databases, distributed replay locks, rate limiting,
and provisioning containers are not defined as HOTP/TOTP calculation
primitives by RFC 4226/6238. Keeping these concerns separate avoids silently
normalizing inputs or pretending stateless code can enforce stateful security
requirements.
