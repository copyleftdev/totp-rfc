#!/bin/sh
set -eu

release_tag=${1-}
package_version=$(
    sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml |
        head -n 1
)

if [ -z "$release_tag" ]; then
    echo "usage: $0 v<package-version>" >&2
    exit 2
fi

if [ "$release_tag" != "v$package_version" ]; then
    echo "release tag '$release_tag' does not match package version 'v$package_version'" >&2
    exit 1
fi

cargo +stable test --all-features --locked --offline
cargo +stable test --no-default-features --locked --offline
cargo +stable package --locked --offline
