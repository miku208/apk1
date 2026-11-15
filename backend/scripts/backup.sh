#!/usr/bin/env bash
# Backup the SQLite database + agent config. Restore is documented in README.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${APP_DIR}/data"
OUT_DIR="${1:-${APP_DIR}/backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET="${OUT_DIR}/lifeform-${STAMP}.tar.gz"

mkdir -p "${OUT_DIR}"
cd "${DATA_DIR}"
# .machine-secret is included so restored tokens keep working.
tar -czf "${TARGET}" lifeform.db lifeform.db-wal lifeform.db-shm agent-config.json .machine-secret 2>/dev/null \
  || tar -czf "${TARGET}" lifeform.db agent-config.json .machine-secret

echo "backup: ${TARGET} ($(du -h "${TARGET}" | cut -f1))"
echo "restore: pm2 stop mikuhost-lifeform && tar -xzf ${TARGET} -C ${DATA_DIR} && pm2 start mikuhost-lifeform"
