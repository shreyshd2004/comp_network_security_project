#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate
exec python3 tftp_server_secure_psk.py \
  --host 0.0.0.0 \
  --port 6969 \
  --root-dir ./files \
  --mode secure_dh
