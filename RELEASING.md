# Release process

Crates.io releases are immutable. Perform every check before publishing.

## One-time repository setup

1. Confirm the `totp-rfc` name is available or owned by the maintainers.
2. Create a GitHub environment named `crates-io`.
3. Add a crates.io API token as the environment secret
   `CARGO_REGISTRY_TOKEN`.
4. Protect the environment with required reviewer approval.
5. Enable GitHub private vulnerability reporting.
6. Apply the description, website, and topics from
   `docs/repository-metadata.md`.

Use a crates.io token scoped to publishing this crate when the registry
supports that scope. Rotate it immediately if it is exposed.

## Release checklist

1. Update `Cargo.toml` using Semantic Versioning.
2. Move relevant entries from `Unreleased` into a dated changelog section.
3. Update the changelog comparison links.
4. Run the full CI, supply-chain, mutation, and package checks.
5. Inspect the exact package:

   ```console
   cargo package --locked
   cargo package --list
   ```

6. Commit the release changes and create a signed `vX.Y.Z` tag.
7. Create a non-prerelease GitHub Release from that exact tag.

Publishing is triggered only when GitHub marks the release as published. The
workflow rejects a tag that does not exactly equal `v` plus the package version,
retests both feature modes, verifies the package, and then runs
`cargo publish --locked`.

For the first release, a maintainer should separately verify ownership and the
resulting crates.io/docs.rs pages before announcing availability.
