#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate
python3 - <<'PY'
from tftpy import TftpServer
import os, sys
root = os.path.abspath("./files")
print("Starting tftpy on 0.0.0.0:6970, root =", root, flush=True)
TftpServer(root).listen("0.0.0.0", 6970)
PY
