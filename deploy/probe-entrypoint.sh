#!/bin/sh
# Administrative test-image entrypoint, never exposed as an ACP/MCP executable.
set -eu
mkdir -p /work/task/home /work/task/tmp
chmod 700 /work/task/home /work/task/tmp
exec "$@"
