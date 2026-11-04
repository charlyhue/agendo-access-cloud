#!/usr/bin/env bash
# Toute la suite : démarre le PostgreSQL de test (scripts/db.sh) puis `cargo test`.
# Les arguments sont passés à `cargo test` (par exemple un nom de test).
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/db.sh up
DATABASE_URL="$(scripts/db.sh url)" exec cargo test "$@"
