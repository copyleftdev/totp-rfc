#!/bin/sh
set -eu

# The suite has fixed case counts and no external inputs. Keep compilation and
# execution serialized, offline, and low priority. GNU timeout is used when
# available; platforms without it still retain the deterministic case bounds.
if command -v timeout >/dev/null 2>&1; then
    exec nice -n 10 timeout 60 cargo test \
        --test adversarial \
        --all-features \
        --locked \
        --offline \
        -j 1 \
        "$@"
fi

exec nice -n 10 cargo test \
    --test adversarial \
    --all-features \
    --locked \
    --offline \
    -j 1 \
    "$@"
