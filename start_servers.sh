#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="./files"

# Start baseline TFTP (tftpy) on UDP 6970
python3 - <<PY > /tmp/tftp_server.log 2>&1 &
from tftpy import TftpServer
import os
root = os.path.abspath("'''$ROOT_DIR'''")
print("Starting tftpy on 0.0.0.0:6970, root =", root, flush=True)
TftpServer(root).listen('0.0.0.0', 6970)
PY
echo $! > /tmp/tftp_server.pid

# Start sTFTP (Diffie–Hellman) on UDP 6969
python3 tftp_server_secure_psk.py \
  --host 0.0.0.0 \
  --port 6969 \
  --root-dir "$ROOT_DIR" \
  --mode secure_dh \
  > /tmp/stftp_server.log 2>&1 &
echo $! > /tmp/stftp_server.pid

echo "Servers started."
echo "TFTP   pid: $(cat /tmp/tftp_server.pid)  log: /tmp/tftp_server.log"
echo "sTFTP  pid: $(cat /tmp/stftp_server.pid) log: /tmp/stftp_server.log"
