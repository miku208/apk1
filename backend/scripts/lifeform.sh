#!/usr/bin/env bash
# MikuHost Lifeform service control (PM2). Does not touch other PM2 processes.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="mikuhost-lifeform"
LOG_DIR="${APP_DIR}/data/logs"

usage() {
  cat <<EOF
Usage: $0 {start|stop|restart|status|logs|pair|doctor}

  start    start (or restart) the backend under PM2
  stop     stop the backend
  restart  restart the backend
  status   PM2 status + local health check
  logs     tail the application log
  pair     generate a pairing code for the Android app
  doctor   run pre-flight checks
EOF
}

case "${1:-}" in
  start)
    cd "${APP_DIR}"
    pm2 describe "${NAME}" >/dev/null 2>&1 \
      && pm2 restart "${NAME}" \
      || pm2 start src/server.mjs --name "${NAME}" --time --max-memory-restart 512M
    pm2 save
    ;;
  stop)
    pm2 stop "${NAME}"
    ;;
  restart)
    pm2 restart "${NAME}"
    ;;
  status)
    pm2 describe "${NAME}" | sed -n '1,20p' || echo "PM2 process ${NAME} not found"
    echo "--- health ---"
    PORT="$(grep -E '^PORT=' "${APP_DIR}/.env" 2>/dev/null | cut -d= -f2 || echo 8888)"
    curl -fsS "http://127.0.0.1:${PORT:-8888}/health" || echo "health check failed"
    echo
    ;;
  logs)
    pm2 logs "${NAME}" --lines 100
    ;;
  pair)
    cd "${APP_DIR}" && node scripts/pair.mjs
    ;;
  doctor)
    cd "${APP_DIR}" && node scripts/doctor.mjs
    ;;
  *)
    usage
    exit 1
    ;;
esac
