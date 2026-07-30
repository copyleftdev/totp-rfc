#!/bin/sh
set -eu

# Timing leakage is statistical and must run optimized. Keep the default pass
# bounded and unobtrusive; use dedicated, pinned hardware for conclusions.
limit=${TIMING_TIMEOUT_SECONDS:-120}
case "$limit" in
    *[!0-9]* | "")
        echo "TIMING_TIMEOUT_SECONDS must be an integer from 10 through 600" >&2
        exit 2
        ;;
esac
if [ "$limit" -lt 10 ] || [ "$limit" -gt 600 ]; then
    echo "TIMING_TIMEOUT_SECONDS must be from 10 through 600" >&2
    exit 2
fi

export CARGO_BUILD_JOBS=1

if [ -n "${TIMING_CPU:-}" ]; then
    case "$TIMING_CPU" in
        *[!0-9]* | "")
            echo "TIMING_CPU must be one non-negative CPU number" >&2
            exit 2
            ;;
    esac
fi

if command -v timeout >/dev/null 2>&1; then
    if [ -n "${TIMING_CPU:-}" ] && command -v taskset >/dev/null 2>&1; then
        exec nice -n 10 timeout "$limit" taskset -c "$TIMING_CPU" \
            cargo bench --bench timing_leakage --locked --offline -j 1 -- "$@"
    fi
    exec nice -n 10 timeout "$limit" \
        cargo bench --bench timing_leakage --locked --offline -j 1 -- "$@"
fi

for argument in "$@"; do
    if [ "$argument" = "--continuous" ]; then
        echo "--continuous requires the timeout command" >&2
        exit 2
    fi
done

if [ -n "${TIMING_CPU:-}" ] && command -v taskset >/dev/null 2>&1; then
    exec nice -n 10 taskset -c "$TIMING_CPU" \
        cargo bench --bench timing_leakage --locked --offline -j 1 -- "$@"
fi

exec nice -n 10 cargo bench \
    --bench timing_leakage \
    --locked \
    --offline \
    -j 1 \
    -- \
    "$@"
