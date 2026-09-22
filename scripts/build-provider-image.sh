#!/usr/bin/env bash
# Build exactly a committed source tree on the selected task-owned Docker VM.
set -euo pipefail

if [[ -z "${DOCKER_HOST:-}" || -n "${DOCKER_CONTEXT:-}" ]]; then
  echo 'Set DOCKER_HOST explicitly and unset DOCKER_CONTEXT' >&2
  exit 2
fi
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
source_sha="$(git rev-parse --verify HEAD)"
if [[ "$(docker version --format '{{.Server.Version}}')" != 29.8.1 ]]; then
  echo 'Selected Docker Engine 29.8.1 is required' >&2
  exit 2
fi
build_root="$(mktemp -d "$repo_root/artifacts/completion/provider-build.XXXXXXXX")"
trap 'rm -rf "$build_root"' EXIT
git archive --format=tar "$source_sha" | tar -xf - -C "$build_root"
runtime_image=debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
if [[ -n "${PROVIDER_BUILD_CACHE_IMAGE:-}" ]]; then
  if [[ -z "${PROVIDER_BUILD_CACHE_ID:-}" || "$(docker image inspect "$PROVIDER_BUILD_CACHE_IMAGE" --format '{{.Id}}')" != "$PROVIDER_BUILD_CACHE_ID" ]]; then
    echo 'Build-cache image identity differs or is missing' >&2
    exit 2
  fi
  test -f "$build_root/deploy/Dockerfile.provider-cached"
  docker build \
    --build-arg "BUILD_CACHE_IMAGE=$PROVIDER_BUILD_CACHE_IMAGE" \
    --build-arg "RUNTIME_IMAGE=$runtime_image" \
    --build-arg "SOURCE_SHA=$source_sha" \
    --tag "llull-buzz-completion-provider:${source_sha:0:12}" \
    --file "$build_root/deploy/Dockerfile.provider-cached" "$build_root"
else
  test -f "$build_root/deploy/Dockerfile.provider"
  docker build --pull \
    --build-arg RUST_IMAGE=rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e \
    --build-arg "RUNTIME_IMAGE=$runtime_image" \
    --build-arg "SOURCE_SHA=$source_sha" \
    --tag "llull-buzz-completion-provider:${source_sha:0:12}" \
    --file "$build_root/deploy/Dockerfile.provider" "$build_root"
fi
docker image inspect "llull-buzz-completion-provider:${source_sha:0:12}" \
  --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
