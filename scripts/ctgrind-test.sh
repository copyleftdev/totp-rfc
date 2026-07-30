#!/bin/sh
set -eu

limit=${CTGRIND_TIMEOUT_SECONDS:-120}
case "$limit" in
    *[!0-9]* | "")
        echo "CTGRIND_TIMEOUT_SECONDS must be an integer from 10 through 300" >&2
        exit 2
        ;;
esac
if [ "$limit" -lt 10 ] || [ "$limit" -gt 300 ]; then
    echo "CTGRIND_TIMEOUT_SECONDS must be from 10 through 300" >&2
    exit 2
fi

for command in cargo gcc valgrind; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "$command is required for the ctgrind evidence pass" >&2
        exit 2
    fi
done
if [ ! -f /usr/include/valgrind/memcheck.h ]; then
    echo "/usr/include/valgrind/memcheck.h is required" >&2
    exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
    echo "GNU timeout is required to enforce the ctgrind resource bound" >&2
    exit 2
fi

export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR=target/ctgrind-harness

nice -n 10 cargo build \
    --manifest-path tools/ctgrind-harness/Cargo.toml \
    --release \
    --locked \
    --offline \
    -j 1

gcc \
    -O1 \
    -g \
    -Wall \
    -Wextra \
    -Werror \
    tools/ctgrind-harness/driver.c \
    target/ctgrind-harness/release/libtotp_ctgrind_harness.a \
    -ldl \
    -lpthread \
    -lm \
    -o target/ctgrind-harness/ctgrind-driver

set +e
nice -n 10 timeout "$limit" valgrind \
    --tool=memcheck \
    --undef-value-errors=yes \
    --track-origins=yes \
    --leak-check=no \
    --errors-for-leak-kinds=none \
    --error-exitcode=99 \
    --exit-on-first-error=yes \
    --log-file=target/ctgrind-harness/calibration.log \
    target/ctgrind-harness/ctgrind-driver \
    --calibrate
calibration_status=$?
set -e
if [ "$calibration_status" -ne 99 ]; then
    echo "ctgrind calibration did not detect the deliberate secret branch" >&2
    echo "calibration exit status: $calibration_status" >&2
    exit 1
fi
echo "ctgrind calibration detected the deliberate secret branch"

set +e
nice -n 10 timeout "$limit" valgrind \
    --tool=memcheck \
    --undef-value-errors=yes \
    --track-origins=yes \
    --leak-check=no \
    --errors-for-leak-kinds=none \
    --error-exitcode=99 \
    --exit-on-first-error=yes \
    --log-file=target/ctgrind-harness/ctgrind.log \
    target/ctgrind-harness/ctgrind-driver
ctgrind_status=$?
set -e
sed -n '1,240p' target/ctgrind-harness/ctgrind.log
if [ "$ctgrind_status" -ne 0 ]; then
    echo "ctgrind secret-taint pass failed with status $ctgrind_status" >&2
    exit "$ctgrind_status"
fi
if ! grep -F "ERROR SUMMARY: 0 errors from 0 contexts" \
    target/ctgrind-harness/ctgrind.log >/dev/null 2>&1; then
    echo "ctgrind log did not contain a zero-error summary" >&2
    exit 1
fi
echo "ctgrind secret-taint evidence passed"
