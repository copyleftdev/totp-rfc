#!/bin/sh
set -eu

limit=${ASSURANCE_CHECK_TIMEOUT_SECONDS:-120}
case "$limit" in
    *[!0-9]* | "")
        echo "ASSURANCE_CHECK_TIMEOUT_SECONDS must be an integer from 30 through 300" >&2
        exit 2
        ;;
esac
if [ "$limit" -lt 30 ] || [ "$limit" -gt 300 ]; then
    echo "ASSURANCE_CHECK_TIMEOUT_SECONDS must be from 30 through 300" >&2
    exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
    echo "GNU timeout is required to enforce assurance resource bounds" >&2
    exit 2
fi

export CARGO_BUILD_JOBS=1

run_bounded() {
    timeout "$limit" nice -n 10 "$@"
}

run_bounded cargo fmt --all -- --check
run_bounded cargo fmt \
    --manifest-path tools/ctgrind-harness/Cargo.toml \
    --all \
    -- \
    --check
run_bounded cargo clippy --all-targets --all-features --locked --offline -- -D warnings
run_bounded env CARGO_TARGET_DIR=target/ctgrind-harness cargo clippy \
    --manifest-path tools/ctgrind-harness/Cargo.toml \
    --release \
    --locked \
    --offline \
    -j 1 \
    -- \
    -D warnings
run_bounded cargo test --all-features --locked --offline -j 1
run_bounded cargo test --no-default-features --locked --offline -j 1
run_bounded cargo +1.85.0 check --all-targets --all-features --locked --offline -j 1
run_bounded env RUSTDOCFLAGS=-Dwarnings cargo doc \
    --all-features \
    --no-deps \
    --locked \
    --offline \
    -j 1
run_bounded cargo package --allow-dirty --locked --offline

scripts/ctgrind-test.sh
scripts/timing-evidence.sh

echo "release assurance evidence passed"
