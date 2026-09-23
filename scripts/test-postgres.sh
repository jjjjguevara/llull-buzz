#!/usr/bin/env bash
# Creates and deletes only this invocation's disposable PostgreSQL container.
set -euo pipefail
cd "$(dirname "$0")/.."
test_filter=''
if (( $# != 0 )); then
  if (( $# != 2 )) || [[ "$1" != --case || "$2" == *[!a-zA-Z0-9_:]* ]]; then
    echo 'Usage: scripts/test-postgres.sh [--case module::case_name]' >&2
    exit 2
  fi
  test_filter="$2"
fi
command -v docker >/dev/null
command -v cargo >/dev/null
test -f Cargo.lock || { echo 'Resolve and commit Cargo.lock first; see docs/implementation/LOCAL-REVIEW.md' >&2; exit 2; }
name="llull-buzz-pg-$(date +%s)-$$-${RANDOM}"
postgres_image='postgres@sha256:efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67'
password="synthetic-$(date +%s)-${RANDOM}-${RANDOM}"
created=false
cleanup() { if "$created"; then docker rm -f "$name" >/dev/null; fi; }
trap cleanup EXIT INT TERM
if docker container inspect "$name" >/dev/null 2>&1; then echo 'Name collision; nothing deleted' >&2; exit 2; fi
docker run -d --name "$name" --label llull-buzz.test=disposable \
  -e POSTGRES_DB=bz_foundation_test -e POSTGRES_USER=buzz_test -e POSTGRES_PASSWORD="$password" \
  -p 127.0.0.1::5432 "$postgres_image" >/dev/null
created=true
# The image's temporary initialization server accepts Unix sockets only. Require
# TCP so readiness cannot succeed just before that temporary server shuts down.
for _ in {1..60}; do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U buzz_test -d bz_foundation_test >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name" pg_isready -h 127.0.0.1 -U buzz_test -d bz_foundation_test
address=$(docker port "$name" 5432/tcp)
case "$address" in 127.0.0.1:*) ;; *) echo 'Unexpected database port binding' >&2; exit 2;; esac
export TEST_DATABASE_URL="postgresql://buzz_test:${password}@${address}/bz_foundation_test"
printf 'candidate=%s\n' "$(git rev-parse HEAD)"
docker image inspect "$postgres_image" --format '{{.Id}} {{json .RepoDigests}}'
# The live relay cases require the separate task-owned stack and are run by
# scripts/local-stack.py check-publication-live. Keep this disposable-DB suite
# focused on the eight cases it can furnish; do not turn absent stack secrets
# into apparent product failures.
run_tests() {
  cargo test --locked -p llull-buzz-provider --test postgres "$@" -- --ignored --test-threads=1 \
    --skip publication::live_provider_publishes_one_signed_event_to_pinned_relay \
    --skip publication::live_relay_response_loss_reconciles_original_event_without_resend
}
if [[ -n "$test_filter" ]]; then
  run_tests "$test_filter"
else
  run_tests
fi
# A real server restart, not a mock repository re-instantiation. Compare durable
# provider records without printing authentication evidence or synthetic keys.
snapshot() {
  docker exec "$name" psql -XAt -U buzz_test -d bz_foundation_test -c "
    SELECT jsonb_build_object(
      'roots',(SELECT jsonb_agg(to_jsonb(r) ORDER BY consumer_id,root_task_id) FROM task_roots r),
      'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attempt_id) FROM attempts a),
      'publications',(SELECT jsonb_agg(to_jsonb(p) ORDER BY publication_id) FROM publications p),
      'bindings',(SELECT jsonb_agg(to_jsonb(e) ORDER BY enrollment_id) FROM enrollments e),
      'observation_counters',(SELECT jsonb_agg(to_jsonb(c) ORDER BY consumer_id) FROM observation_counters c),
      'observations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY consumer_id,sequence) FROM observations o),
      'observation_offsets',(SELECT jsonb_agg(to_jsonb(o) ORDER BY consumer_id,module_id,context_domain,recovery_epoch) FROM observation_offsets o),
      'observation_receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY consumer_id,cursor_sha256) FROM observation_receipts r),
      'epoch',(SELECT recovery_epoch FROM provider_control WHERE singleton=1),
      'evidence_count',(SELECT count(*) FROM admission_evidence));" | sha256sum | cut -d ' ' -f 1
}
before=$(snapshot)
docker restart "$name" >/dev/null
for _ in {1..60}; do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U buzz_test -d bz_foundation_test >/dev/null 2>&1; then break; fi
  sleep 1
done
after=$(snapshot)
test "$before" = "$after" || { echo 'Durable records changed across PostgreSQL restart' >&2; exit 1; }
printf 'PostgreSQL restart preserved roots, effects, bindings, publication, observations and recovery epoch: %s\n' "$after"
