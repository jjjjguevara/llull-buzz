#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null
command -v timeout >/dev/null
test -f Cargo.lock || { echo 'Resolve and commit Cargo.lock first' >&2; exit 2; }
base="llull-buzz-probe-$(date +%s)-$$-${RANDOM}"
image="${base}:local"
containers=()
image_created=false
cleanup() {
  for name in "${containers[@]-}"; do
    [ -n "$name" ] || continue
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  if "$image_created"; then docker image rm "$image" >/dev/null || true; fi
}
trap cleanup EXIT INT TERM
if docker image inspect "$image" >/dev/null 2>&1; then echo 'Image name collision; nothing deleted' >&2; exit 2; fi
docker build --force-rm -f deploy/Dockerfile.probe -t "$image" .
image_created=true
printf 'candidate=%s\n' "$(git rev-parse HEAD)"
docker image inspect "$image" --format '{{.Id}}'
run() {
  local name="$base-$1"; shift
  if docker container inspect "$name" >/dev/null 2>&1; then echo 'Container name collision' >&2; exit 2; fi
  containers+=("$name")
  timeout 90s docker run --rm --name "$name" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1 \
    --tmpfs /work/task:rw,nosuid,nodev,noexec,size=16m,mode=700,uid=65532,gid=65532 \
    -e BUZZ_PRIVATE_KEY=synthetic-forbidden -e SSH_AUTH_SOCK=/synthetic/socket \
    -e HTTPS_PROXY=https://proxy.synthetic.invalid -e NODE_OPTIONS=synthetic-forbidden \
    "$image" "$@"
}
# Actual executable launch, ACP2 session and rmcp stdio negotiation; no model prompt.
run protocol /opt/llull/bin/llull-buzz-launch probe
# Kernel-enforced negative probes; these are not replaced by mocks or text scans.
run network /bin/bash -c '
set -eu
test "$(id -u)" = 65532
test ! -e /var/run/docker.sock
test ! -e /root/.ssh
test ! -e /root/.config
test ! -e /host
if touch /opt/llull/forbidden 2>/dev/null; then exit 10; fi
if timeout 3 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then exit 11; fi
if timeout 3 bash -c "exec 3<>/dev/tcp/169.254.169.254/80" 2>/dev/null; then exit 12; fi
printf "process/filesystem/network negative probes passed\n"
'
