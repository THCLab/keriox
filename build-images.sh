#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Compute git version suffix
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || true)
GIT_DIRTY=$(git status --porcelain 2>/dev/null || true)

if [ -n "$GIT_SHA" ]; then
    if [ -n "$GIT_DIRTY" ]; then
        GIT_VERSION_SUFFIX="-dirty-${GIT_SHA}"
    else
        GIT_VERSION_SUFFIX="-${GIT_SHA}"
    fi
else
    GIT_VERSION_SUFFIX=""
fi

# Allow image tag override, default to git sha or "latest"
TAG="${1:-${GIT_SHA:-latest}}"

echo "Building with GIT_VERSION_SUFFIX=${GIT_VERSION_SUFFIX} tag=${TAG}"

docker build \
    --build-arg GIT_VERSION_SUFFIX="$GIT_VERSION_SUFFIX" \
    -f witness.Dockerfile \
    -t keriox-witness:"$TAG" \
    .

docker build \
    --build-arg GIT_VERSION_SUFFIX="$GIT_VERSION_SUFFIX" \
    -f watcher.Dockerfile \
    -t keriox-watcher:"$TAG" \
    .

echo "Built keriox-witness:${TAG} and keriox-watcher:${TAG}"
