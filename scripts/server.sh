#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PID_FILE="$ROOT_DIR/.gateway.pid"
LOG_FILE="$ROOT_DIR/gw.log"

is_running() {
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

start() {
  if is_running; then
    echo "running pid=$(cat "$PID_FILE")"
    exit 0
  fi
  setsid -f sh -c "cd '$ROOT_DIR' && exec node src/server.js >> '$LOG_FILE' 2>&1"
  sleep 1
  PID=$(ps -ef | awk '/node src\/server.js/ && $0 !~ /awk/ {print $2; exit}')
  if [ -n "${PID:-}" ]; then
    echo "$PID" > "$PID_FILE"
    echo "started pid=$PID"
    exit 0
  fi
  echo "start failed"
  exit 1
}

stop() {
  if ! is_running; then
    rm -f "$PID_FILE"
    echo "not running"
    exit 0
  fi
  PID=$(cat "$PID_FILE")
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
