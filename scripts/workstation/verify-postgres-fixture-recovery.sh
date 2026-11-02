#!/usr/bin/env bash
# Synthetic, isolated PostgreSQL dump/restore verification; NO user backups.
set -Eeuo pipefail
umask 077

fail() { printf 'NO-GO: %s\n' "$1" >&2; exit 3; }
usage() { printf 'Usage: %s --check | --run --acknowledge SYNTHETIC_ONLY\n' "$0" >&2; exit 2; }

[[ "$#" -gt 0 ]] || usage
case "$1" in
  --check) [[ "$#" -eq 1 ]] || usage; mode=check ;;
  --run)
    [[ "$#" -eq 3 && "$2" == --acknowledge && "$3" == SYNTHETIC_ONLY ]] || usage
    mode=run ;;
  *) usage ;;
esac

# Only a locally cached, immutable image ID is accepted. No pull/network.
image="$(printenv NABLA_POSTGRES_FIXTURE_IMAGE_SHA256 2>/dev/null || true)"
[[ "${image}" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'explicit local image SHA256 required'
command -v docker >/dev/null 2>&1 || fail 'docker missing'
# A workstation may have a remote TrueNAS Docker context; refuse it.
docker_host="$(printenv DOCKER_HOST 2>/dev/null || true)"
[[ -z "${docker_host}" || "${docker_host}" == unix:///* ]] || fail 'remote DOCKER_HOST prohibited'
docker_endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" || fail 'Docker context unavailable'
[[ "${docker_endpoint}" == unix:///* ]] || fail 'local Unix Docker context required'
local_image="$(docker image inspect --format '{{.Id}}' "${image}" 2>/dev/null)" || fail 'image not cached'
[[ "${local_image}" == "${image}" ]] || fail 'image digest mismatch'
if [[ "${mode}" == check ]]; then
  printf '%s\n' 'NO-GO: local synthetic fixture image available; restore NOT_RUN'
  exit 0
fi

# Docker is explicit opt-in: no host ports, no mount, no network or secrets.
name="nabla-postgres-fixture-$$-${RANDOM}"
container_created=false
cleanup() {
  if [[ "${container_created}" == true ]]; then
    docker rm -f -- "${name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

docker run --detach --rm --pull=never --network none --read-only \
  --name "${name}" --memory 512m --pids-limit 128 \
  --tmpfs /var/lib/postgresql:rw,nosuid,nodev,size=256m \
  --tmpfs /var/run/postgresql:rw,nosuid,nodev,size=16m \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e PGDATA=/var/lib/postgresql/data/pgdata \
  "${image}" >/dev/null || fail 'isolated fixture container failed'
container_created=true

ready=false
for _ in $(seq 1 40); do
  if docker exec --user postgres "${name}" pg_isready -U postgres -q >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]] || fail 'isolated fixture did not become ready'

# All test content is synthetic and stays in the ephemeral container.
docker exec --user postgres "${name}" createdb -U postgres nabla_fixture_source >/dev/null 2>&1 || fail 'fixture source DB creation failed'
docker exec --user postgres "${name}" createdb -U postgres nabla_fixture_restored >/dev/null 2>&1 || fail 'fixture target DB creation failed'
docker exec --user postgres "${name}" psql -U postgres -d nabla_fixture_source -v ON_ERROR_STOP=1 \
  -q -c "CREATE TABLE public.nabla_restore_fixture (id integer PRIMARY KEY, payload text NOT NULL); INSERT INTO public.nabla_restore_fixture VALUES (42, 'synthetic-fixture');" \
  >/dev/null 2>&1 || fail 'fixture SQL failed'
docker exec --user postgres "${name}" pg_dump -U postgres -Fc -f /tmp/nabla_fixture.dump nabla_fixture_source \
  >/dev/null 2>&1 || fail 'synthetic dump failed'
docker exec --user postgres "${name}" pg_restore -U postgres -e -1 -d nabla_fixture_restored /tmp/nabla_fixture.dump \
  >/dev/null 2>&1 || fail 'synthetic restore failed'
result="$(docker exec --user postgres "${name}" psql -U postgres -d nabla_fixture_restored -Atq \
  -c 'SELECT id, payload FROM public.nabla_restore_fixture' 2>/dev/null)" || fail 'fixture query failed'
[[ "${result}" == '42|synthetic-fixture' ]] || fail 'fixture content mismatch'
printf '%s\n' 'PASS: isolated synthetic PostgreSQL dump and restore (NOT a private backup recovery)'
