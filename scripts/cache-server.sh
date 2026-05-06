#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CACHE_DIR="$ROOT_DIR/services/prompt-cache"
PID_FILE="$ROOT_DIR/.promptcache.pid"
LOG_FILE="$ROOT_DIR/promptcache.log"

: "${CACHE_PORT:=8080}"
: "${CACHE_STORAGE_PATH:=$ROOT_DIR/data/promptcache}"
: "${CACHE_AUTH_TOKEN:=pc_local_token}"
: "${CACHE_EMBEDDING_PROVIDER:=openai}"
: "${CACHE_OPENAI_BASE_URL:=https://api.openai.com/v1}"
: "${CACHE_OPENAI_EMBED_MODEL:=text-embedding-3-small}"
: "${CACHE_OPENAI_VERIFY_MODEL:=gpt-4o-mini}"

is_running() {
  FOUND_PID=$(find_pid || true)
  if [ -n "$FOUND_PID" ]; then
    echo "$FOUND_PID" > "$PID_FILE"
  fi
  if [ ! -f "$PID_FILE" ]; then
    return 1
  fi
  PID=$(cat "$PID_FILE" 2>/dev/null || true)
  if [ -z "$PID" ]; then
    return 1
  fi
  if kill -0 "$PID" 2>/dev/null; then
    return 0
  fi
  return 1
}

find_pid() {
  for pid in $(ps -ef | awk '/[[:space:]]\.\/api([[:space:]]|$)/ && $0 !~ /awk/ {print $2}'); do
    if [ ! -d "/proc/$pid" ]; then
      continue
    fi
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
    if [ "$cwd" = "$CACHE_DIR" ]; then
      echo "$pid"
      return 0
    fi
  done
  return 1
}

ensure_binary() {
  if [ -x "$CACHE_DIR/api" ]; then
    return 0
  fi
  echo "building prompt-cache..."
  (cd "$CACHE_DIR" && go build -o api ./cmd/api)
}

start() {
  if is_running; then
    echo "running pid=$(cat "$PID_FILE")"
    exit 0
  fi
  ensure_binary
  mkdir -p "$CACHE_STORAGE_PATH"
  setsid -f sh -c "
    cd '$CACHE_DIR' && \
    PORT='$CACHE_PORT' \
    STORAGE_PATH='$CACHE_STORAGE_PATH' \
    API_AUTH_TOKEN='$CACHE_AUTH_TOKEN' \
    EMBEDDING_PROVIDER='$CACHE_EMBEDDING_PROVIDER' \
    OPENAI_BASE_URL='$CACHE_OPENAI_BASE_URL' \
    OPENAI_EMBED_MODEL='$CACHE_OPENAI_EMBED_MODEL' \
    OPENAI_VERIFY_MODEL='$CACHE_OPENAI_VERIFY_MODEL' \
    exec ./api >> '$LOG_FILE' 2>&1
  "
  sleep 1
  PID=$(find_pid || true)
  if [ -n "${PID:-}" ]; then
    echo "$PID" > "$PID_FILE"
    echo "started pid=$PID"
    exit 0
  fi
  echo "start failed"
  exit 1
}

stop() {
  PID=""
  if is_running; then
    PID=$(cat "$PID_FILE")
  else
    PID=$(find_pid || true)
    if [ -z "$PID" ]; then
      rm -f "$PID_FILE"
      echo "not running"
      exit 0
    fi
  fi
  kill "$PID" 2>/dev/null || true
  sleep 1
  if kill -0 "$PID" 2>/dev/null; then
    kill -9 "$PID" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  echo "stopped"
}

status() {
  if is_running; then
    PID=$(cat "$PID_FILE")
    echo "running pid=$PID"
    exit 0
  fi
  echo "not running"
  exit 1
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop || true; start ;;
  status) status ;;
  logs) tail -n 80 "$LOG_FILE" ;;
  *)
    echo "usage: $0 {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
