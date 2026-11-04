#!/usr/bin/env bash
# PostgreSQL de test en conteneur, pour `#[sqlx::test]` (une base jetable par test).
#
#   scripts/db.sh up     démarre le conteneur (idempotent) et attend qu'il réponde
#   scripts/db.sh down   l'arrête et le supprime (les données sont jetables)
#   scripts/db.sh url    affiche l'URL à mettre dans DATABASE_URL
#
# Le conteneur n'écoute que sur 127.0.0.1 et n'a pas de mot de passe (trust) : c'est une base
# de test locale, sans donnée réelle. Port : AGENDO_CLOUD_PG_PORT (54340 par défaut).
set -euo pipefail

NAME=agendo-access-cloud-pg
IMAGE=postgres:17-alpine
PORT="${AGENDO_CLOUD_PG_PORT:-54340}"
URL="postgres://postgres@127.0.0.1:${PORT}/postgres"

case "${1:-}" in
  up)
    if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
      docker rm -f "$NAME" >/dev/null 2>&1 || true
      docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:5432" \
        -e POSTGRES_HOST_AUTH_METHOD=trust --tmpfs /var/lib/postgresql/data "$IMAGE" >/dev/null
    fi
    for _ in $(seq 1 50); do
      docker exec "$NAME" pg_isready -U postgres -q && exit 0
      sleep 0.2
    done
    echo "PostgreSQL de test injoignable" >&2
    exit 1
    ;;
  down) docker rm -f "$NAME" >/dev/null ;;
  url) echo "$URL" ;;
  *) echo "usage : scripts/db.sh up|down|url" >&2; exit 2 ;;
esac
