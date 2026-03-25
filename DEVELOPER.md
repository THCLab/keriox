# Developer Guide

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

Run `cargo release` from the workspace root, replacing `<VERSION>` with the
next semver version (e.g. `0.17.10`) or use minor, major, patch, rc tag:

```bash
cargo release <VERSION>
```

This will, in order:
- Run `git cliff` to regenerate `CHANGELOG.md` for the new version tag
- Update `version` in every crate's `Cargo.toml`
- Create a commit: `chore: Release v<VERSION>`
- Create a git tag `v<VERSION>`

### 2. Push the commit and tag

```bash
git push origin main
git push origin v<VERSION>
```

Pushing a `v*` tag triggers the CI workflows for Docker image builds and crates.io publishing.

### 3. What the CI does automatically

| Workflow | Trigger | Action |
|----------|---------|--------|
| `docker-images.yml` | `v*` tag pushed | Builds `witness` and `watcher` images, pushes to the registry, creates a GitHub release |
| `publish.yml` | `v*` tag pushed | Publishes `keri-core` to crates.io |

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
