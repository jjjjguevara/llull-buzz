#!/usr/bin/env bash
# Build pinned, unmodified Buzz executables plus selected-source notices.
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
build_root="$(mktemp -d "$repo_root/artifacts/completion/upstream-build.XXXXXXXX")"
trap 'rm -rf "$build_root"' EXIT
git archive --format=tar --output="$build_root/source.tar" "$source_sha"
tar -xf "$build_root/source.tar" -C "$build_root"
rm "$build_root/source.tar"
image="llull-buzz-completion-upstream:01b6174-${source_sha:0:12}"
docker build --pull \
  --build-arg RUST_IMAGE=rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e \
  --build-arg RUNTIME_IMAGE=debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 \
  --build-arg "SOURCE_SHA=$source_sha" \
  --tag "$image" --file "$build_root/deploy/Dockerfile.upstream" "$build_root"
docker image inspect "$image" \
  --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "org.llull.buzz.upstream"}}'
