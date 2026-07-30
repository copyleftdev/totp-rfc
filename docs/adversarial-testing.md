# Adversarial testing

This suite treats every public input as hostile while keeping execution
deterministic, reviewable, and small enough for ordinary CI. It complements
the RFC vectors and mutation sweep; it does not claim that tests prove a
cryptographic implementation secure.

## Threat matrix

| Attack class | Defensive evidence | Bound |
| --- | --- | --- |
| Whitespace, signs, separators, control bytes, Unicode digits, homoglyphs, bidi controls, and zero-width characters | Strict parser corpus plus every non-decimal ASCII byte in every six-digit position | Fewer than 1,000 structured cases |
| Oversized candidate used for allocation or parsing denial of service | A 64 KiB candidate is rejected by its byte length before numeric parsing | One fixed allocation |
| Unexpected parser/verifier panics | Deterministic ASCII corpus drives parsing and both window verifiers at arithmetic boundaries | 2,048 cases |
| Dynamic-truncation, endianness, modulus, or hash-selection defect | Independent HMAC oracle compares HOTP and all TOTP algorithms across all widths, key lengths, random counters, and integer boundaries | Under 7,000 generated codes |
| Algorithm downgrade or substitution | SHA-1, SHA-256, and SHA-512 codes are cross-submitted to mismatched verifiers | One collision-checked vector |
| Secret, digit-width, epoch, or period confusion | Codes are submitted under deliberately mismatched immutable configurations | Fixed matrix |
| Validation-window off-by-one | Every step inside a bounded radius is accepted and the immediate neighbors are rejected | Radius of eight steps |
| Decimal collision changes first-match semantics | A bounded birthday search finds a real six-digit collision and proves HOTP and TOTP return the first matching counter | At most 4,096 generated codes |
| Counter underflow or overflow | HOTP and TOTP searches at zero and `u64::MAX` prove that arithmetic cannot wrap into an accepted code | Four-step edge windows |
| Replay mistaken for a primitive guarantee | Repeated verification demonstrates stateless behavior and asserts the exact counter state applications must persist | One HOTP and one TOTP case |
| Weak or extreme secret length | Every rejected length below 128 bits, the exact minimum, and a 4 KiB HMAC key are exercised | 17 boundaries |
| Accidental secret disclosure | Compile-fail documentation proves `Secret` has no `Debug` output and no public byte accessor | Two compiler tests |

All corpus sizes are constants in `tests/adversarial.rs`. There are no random
seeds, network calls, sleeps, recursive generators, unbounded search spaces,
or new test dependencies.

## Timing-leakage laboratory

Well-formed codes are compared with `subtle::ConstantTimeEq`, and window
searches continue after a match. Malformed syntax is intentionally rejected
early because syntax and length are attacker-controlled public data.

That comparison guarantee does not make the full HMAC generation and
verification path universally constant-time. Those paths inherit behavior
from the RustCrypto backend, compiler, target instruction set, caches,
frequency control, and other microarchitectural details. The laboratory is
designed to expose statistically distinguishable classes at that complete
boundary.

The separate `timing_leakage` bench uses `dudect-bencher` in optimized release
mode. Dudect divides hostile inputs into two distributions, crops the runtime
distributions at many percentiles, performs roughly 100 Welch t-tests, and
reports the largest absolute t-value and normalized effect size.

For release evidence, run three calibrated passes and retain the
machine-readable result:

```console
TIMING_CPU=3 ./scripts/timing-evidence.sh
```

The release threshold applies to secret-content, isolated equality, and
window-position probes. A probe exceeding an absolute t-value of five in at
least two independent runs fails the evidence gate; a single excursion is
retained as an advisory. Counter and timestamp classes are retained as
diagnostics but do not gate because they are public protocol inputs.

The probes target:

- a correct code versus random well-formed codes;
- first-digit versus last-digit mismatches with the same false result;
- fixed versus random secret-key bytes during SHA-1, SHA-256, and SHA-512
  generation;
- low versus high-Hamming-weight counters;
- current-step versus edge-of-window successful matches;
- malformed versus well-formed input as an intentionally leaky calibration
  control.

Run the bounded pass:

```console
./scripts/timing-test.sh
```

On Linux, isolate a quiet core and pin the process:

```console
TIMING_CPU=3 ./scripts/timing-test.sh
```

Use `--filter` to isolate one hypothesis. The wrapper caps execution at 120
seconds by default, accepts at most 600 seconds, uses one build job, and lowers
scheduler priority. Each probe has exactly 30,000 measurements with a
deterministic random seed; the complete eight-probe pass performs at most
240,000 timed operations.

An absolute t-value above five is evidence worth investigating, not a
standalone vulnerability verdict. A value below five does not prove constant
time. Repeat suspicious results on a quiet bare-metal host with a pinned core,
fixed CPU frequency, disabled turbo and power management, minimal interrupts,
multiple fresh process runs, and the exact release binary. Investigate stable
secret-class signals even when library control flow is input-independent:
cryptographic dependencies, compiler output, caches, and data-dependent
microarchitectural effects remain in scope. The malformed-input calibration
should show a large signal; if it does not, the environment is too noisy to
trust.

The manual GitHub workflow is advisory only. Shared runners, virtualized
clocks, frequency scaling, caches, and unrelated tenants can cause both false
positives and false confidence, so timing results never gate ordinary CI.

## Secret-taint analysis

The bounded `ctgrind` pass marks shared-secret bytes undefined with Valgrind
Memcheck client requests. Memcheck then reports if tainted values influence a
branch or memory address. The runner first executes an intentional
secret-dependent branch and requires detection, then exercises HOTP and every
TOTP algorithm:

```console
./scripts/ctgrind-test.sh
```

The harness lives under `tools/ctgrind-harness/` and is excluded from the
published crate. It uses one build job, reduced priority, `-O1`, locked offline
dependencies, and a 120-second default timeout.

See the [security assurance case](security-assurance.md) for the exact claim,
release criteria, and limitations.

## Stateful controls outside the crate

The library cannot enforce controls requiring shared application state:

- per-account and distributed failure throttling;
- atomic HOTP counter advancement;
- TOTP replay databases;
- credential lockout and recovery policy;
- encrypted secret storage and memory locking;
- secure provisioning and transport.

The replay tests intentionally show this boundary. A second validation returns
the same match until the caller atomically records and enforces the returned
counter state.

## Running the suite

Run only the bounded attacker suite:

```console
./scripts/adversarial-test.sh
```

The wrapper uses one Cargo job, reduced scheduler priority, offline dependency
resolution, and a 60-second wall-clock limit when the platform provides the
`timeout` command.
