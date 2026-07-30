# Contributing to totp-rfc

Thank you for helping improve `totp-rfc`. Changes should preserve the crate's
small, strict, security-oriented primitive layer.

## Before opening a pull request

1. Explain the concrete interoperability, correctness, or usability problem.
2. Link the relevant RFC section or another authoritative specification.
3. Keep provisioning, storage, networking, and service policy outside the
   primitive layer unless the boundary itself must change.
4. Add focused regression tests for every behavior change.
5. Update public API and security documentation where applicable.

Never commit production shared secrets, live OTP codes, API tokens, or private
user data. RFC test keys and clearly synthetic fixtures are acceptable.

## Local checks

The project supports Rust 1.85.0 and current stable Rust. Run:

```console
cargo fmt --all -- --check
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo package --allow-dirty
```

If `cargo-deny` is installed, also run:

```console
cargo deny check
```

Cryptographic or validation changes should pass the mutation suite:

```console
./scripts/mutation-test.sh
```

Performance-sensitive changes should include before-and-after Criterion
results from the same machine:

```console
nice -n 10 cargo bench --bench primitives --offline -j 1
```

## Pull requests

Keep commits reviewable and avoid unrelated formatting or dependency changes.
The pull request description should cover:

- specification and security impact;
- public API or SemVer impact;
- `no_std` and MSRV impact;
- tests and independent evidence;
- benchmark results when performance may change.

All CI checks must pass. Review may request additional RFC vectors, mutation
tests, or misuse-resistance documentation.
