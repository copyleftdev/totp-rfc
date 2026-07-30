# Security assurance case

This document defines the evidence that supports `totp-rfc`'s security claims.
It deliberately distinguishes proof about a specific property and build from
a universal claim about every compiler, processor, operating system, and
deployment.

## Supported claim

For well-formed OTP values, code equality does not branch or address memory
based on the compared values. HMAC generation does not branch or address
memory based on secret bytes in the exercised SHA-1, SHA-256, and SHA-512
paths. Dynamic truncation reads all 16 RFC-permitted windows and selects the
required value with a constant-time mask. Bounded validation windows perform
every representable HMAC calculation and select the first match without
branching on its position.

Malformed syntax may return early. Candidate syntax, length, the HOTP counter,
the TOTP timestamp, and system parameters are public inputs. Final
success/failure and returned match state are also public API outputs.

## Evidence layers

| Layer | Property | Evidence | Release decision |
| --- | --- | --- | --- |
| Specification | RFC outputs and boundary behavior | RFC 4226/6238 vectors, independent HMAC oracle, arithmetic and window tests | Mandatory deterministic gate |
| Secret taint | Secret bytes do not affect branches or memory addresses on the analyzed binary paths | Calibrated Valgrind/Memcheck harness for HOTP and all TOTP algorithms | Zero errors required |
| Statistical timing | Selected runtime distributions are not distinguishable on the measurement host | Three calibrated dudect runs, 30,000 samples per probe per run | A secret, equality, or window-position probe must not exceed `|t| = 5` in two or more independent runs |
| Mutation resistance | Tests detect viable source mutations | Serialized, time-limited mutation sweep | Required for cryptographic or validation changes |
| Portability | Declared build surface remains valid | Stable Rust, Rust 1.85 MSRV, `no_std`, rustdoc, Clippy, and package gates | Mandatory deterministic gate |

The taint runner first executes a deliberate secret-dependent branch and
requires Memcheck to reject it with the configured error exit code. A clean
real pass is accepted only after that calibration succeeds. The real harness
marks RFC test secrets undefined, then exercises generation, correct-code
verification, and wrong-code verification before explicitly declassifying
public return values.

The timing evidence runner records raw output, tool and host metadata, and a
tab-separated summary under `target/timing-evidence/`. Counter-class results
remain in the evidence but do not gate release because counters and timestamps
are public protocol inputs. The malformed-input probe must exceed the
threshold as a positive calibration. A single sensitive-probe excursion is
retained as an advisory; repetition in at least two independent process runs
fails the release evidence. This avoids certifying from one favorable sample
without treating one result among hundreds of cropped t-tests as conclusive.

## Reproduce the assurance bundle

Install Valgrind, GCC, stable Rust, and Rust 1.85.0. On Linux, choose a quiet
CPU allowed by the process affinity mask:

```console
TIMING_CPU=3 ./scripts/assurance-test.sh
```

The command uses one Cargo job, reduced scheduler priority, offline locked
dependencies, per-check timeouts, three finite timing passes, and a bounded
taint run. Mutation testing remains separate because it has a materially
larger resource budget:

```console
./scripts/mutation-test.sh
```

The manual `Constant-time evidence` workflow reproduces the calibrated taint
analysis. The manual `Timing leakage advisory` workflow runs three statistical
passes and uploads the raw data, summary, and environment metadata for 30
days.

## Limits and residual risk

This is not a mathematical proof of universal constant-time execution.
Memcheck dynamically covers the exercised native paths and detects
secret-dependent control flow and addresses; it does not model
operand-dependent instruction latency, power, electromagnetic leakage, or
unexercised target-specific code. Dudect can find distinguishable timing
distributions but cannot prove their absence.

Release evidence must therefore be regenerated after compiler, target,
optimization, RustCrypto, or relevant CPU changes. High-assurance deployments
should repeat statistical analysis on representative bare-metal hardware and
independently review the emitted machine code. Application controls such as
rate limiting, replay prevention, secret storage, transport security, and
process isolation remain outside this crate.
