# Developer Guide

For performance instrumentation, the `perf_watcher` harness, and how to
A/B-test transport-layer changes, see [`PERFORMANCE.md`](PERFORMANCE.md).

## Prerequisites

- Rust toolchain (stable) — [rustup.rs](https://rustup.rs)
- [`cargo-release`](https://github.com/crate-ci/cargo-release): `cargo install cargo-release`
- Docker with Buildx support

---

## Releasing

Releases are version-bump commits followed by a git tag. Pushing the tag
triggers the CI pipeline that builds and publishes Docker images and publishes
crates to crates.io.

### 1. Bump the version

Releases build against crates.io dependencies only. A local
`[patch.crates-io]` (e.g. pointing `cesrox` at a sibling checkout) must not be
committed: the CI checkout has no such directory and publishing fails.

Run `cargo release` from the workspace root on `master`, replacing
`<VERSION>` with the next semver version (e.g. `0.17.10`) or use minor, major,
patch, rc tag. It is a dry run by default; check its output, then repeat with
`--execute`. The dry run still runs the `git cliff` hook, so review the
regenerated `CHANGELOG.md` and restore it (`git checkout CHANGELOG.md`) before
executing:

```bash
cargo release <VERSION>
cargo release <VERSION> --execute
```

This will, in order:
- Run `git cliff` to regenerate `CHANGELOG.md` for the new version tag
- Update `version` in every crate's `Cargo.toml`
- Create a commit: `chore: Release`
- Create a git tag `v<VERSION>`
- Push the current branch and the tag to `origin`

`cargo release` never publishes to crates.io itself (every crate sets
`publish = false` under `[package.metadata.release]`); CI does.

### 2. Push the commit and tag

`cargo release --execute` pushes both itself. If it was run with `--no-push`,
push them by hand:

```bash
git push origin master
git push origin v<VERSION>
```

Pushing a `v*` tag triggers the CI workflows for Docker image builds and crates.io publishing.

### 3. What the CI does automatically

| Workflow | Trigger | Action |
|----------|---------|--------|
| `docker-images.yml` | `v*` tag pushed | Builds `witness` and `watcher` images, pushes to the registry, creates a GitHub release |
| `publish.yml` | `v*` tag pushed | Publishes every workspace crate not marked `publish = false` in `[package]` (`keri-core`, `teliox`, `keri-controller`, `keri-keyprovider`, `keri-sdk`) to crates.io, in dependency order, skipping versions already published |

---

## Docker images

### Building locally

Build the witness image:

```bash
docker build -f witness.Dockerfile -t keriox-witness:<VERSION> .
```

Build the watcher image:

```bash
docker build -f watcher.Dockerfile -t keriox-watcher:<VERSION> .
```

### Registry

Images are published to the Harbor registry at:

```
docker push harbor.colossi.network:4443/hcf/<name>
```

Published tags follow the pattern:

```
harbor.colossi.network:4443/hcf/keriox-witness:<VERSION>
harbor.colossi.network:4443/hcf/keriox-watcher:<VERSION>
```

To pull a specific release:

```bash
docker pull harbor.colossi.network:4443/hcf/keriox-witness:<VERSION>
docker pull harbor.colossi.network:4443/hcf/keriox-watcher:<VERSION>
```
