#!/bin/sh
set -eu

# Mutation testing is intentionally serialized at both levels:
# - one mutant worker;
# - one shared Cargo/rustc jobserver token.
#
# Explicit timeouts prevent a pathological mutation from hanging indefinitely.
# nice lowers scheduling priority so the sweep stays unobtrusive.
exec nice -n 10 cargo mutants \
    --jobs 1 \
    --jobserver-tasks 1 \
    --timeout 10 \
    --build-timeout 30 \
    "$@"
