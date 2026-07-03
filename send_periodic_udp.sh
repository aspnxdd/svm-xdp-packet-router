#!/usr/bin/env bash
set -euo pipefail

HOST="127.0.0.1"
PORT="8001"
FIXED_PAYLOAD="01 00 00 00 11 11 11 11"

while true; do
  if ((RANDOM % 2)); then
    payload="$(npx tsx scripts/src/send_random_shreds.ts)"
    printf '[%(%Y-%m-%dT%H:%M:%S%z)T] sending random_shred bytes=%d to %s:%s\n' -1 "$(( ${#payload} / 2 ))" "$HOST" "$PORT"
    ./send_udp.sh "$HOST" "$PORT" "$payload"
  else
    printf '[%(%Y-%m-%dT%H:%M:%S%z)T] sending fixed_payload bytes=8 to %s:%s payload="%s"\n' -1 "$HOST" "$PORT" "$FIXED_PAYLOAD"
    ./send_udp.sh "$HOST" "$PORT" "$FIXED_PAYLOAD"
  fi

  delay_ms=$((500 + RANDOM % 501))
  printf 'sleeping %dms\n' "$delay_ms"
  sleep "$(printf '%d.%03d' "$((delay_ms / 1000))" "$((delay_ms % 1000))")"
done
