#!/usr/bin/env bash
set -euo pipefail

SERVER="130.207.114.26"             # shuttle1
SERVER_USER="${SERVER_USER:-$USER}" # for SFTP path
PORT_TFTP=6970
PORT_STFTP=6969

# Files and payload sizes (bytes)
FILES=("f_4k.bin" "f_32k.bin" "f_2m.bin")
declare -A BYTES=( ["f_4k.bin"]=4096 ["f_32k.bin"]=32768 ["f_2m.bin"]=2097152 )

RUNS_TFTP=5
RUNS_STFTP=5
RUNS_SFTP=1          # cold SFTP: exactly one transfer per file (fresh auth each time)

DL_DIR="downloads"
mkdir -p "$DL_DIR"

iface_from_route(){ ip route get "$SERVER" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
read_iface_bytes(){ local i=$1; echo $(( $(< /sys/class/net/$i/statistics/rx_bytes) + $(< /sys/class/net/$i/statistics/tx_bytes) )); }
time_cmd(){ /usr/bin/time -p bash -c "$1" 2>&1 | awk '/^real/ {print $2}' || echo "NA"; }

calc_overhead(){ python3 - "$@" <<'PY'
import sys
wire=int(sys.argv[1]); payload=int(sys.argv[2])
print("NA" if wire<=0 else round((wire-payload)*100.0/payload,2))
PY
}
calc_goodput(){ python3 - "$@" <<'PY'
import sys
payload=int(sys.argv[1]); t=sys.argv[2]
try:
    t=float(t); print(round(payload*8.0/t/1e6,3) if t>0 else "NA")
except: print("NA")
PY
}

IFACE=$(iface_from_route); [[ -z "$IFACE" ]] && { echo "Could not resolve interface to $SERVER"; exit 1; }
echo "Using interface: $IFACE"

OUT="results_$(date +%Y%m%d_%H%M%S)_cold_sftp.csv"
echo "proto,file,bytes,run,elapsed_s,wire_bytes,overhead_pct,goodput_Mbps" > "$OUT"

for f in "${FILES[@]}"; do
  payload=${BYTES[$f]}
  [[ -z "${payload:-}" ]] && { echo "Unknown payload size for $f"; exit 1; }

  # ---- TFTP (tftpy) ----
  for r in $(seq 1 $RUNS_TFTP); do
    rm -f "$DL_DIR/$f"
    pre=$(read_iface_bytes "$IFACE")
    elapsed=$(time_cmd "python3 - <<PY
from tftpy import TftpClient
c = TftpClient('$SERVER', $PORT_TFTP)
c.download('$f', '$DL_DIR/$f')
PY
")
    post=$(read_iface_bytes "$IFACE"); wire=$((post-pre))
    echo "TFTP,$f,$payload,$r,$elapsed,$wire,$(calc_overhead $wire $payload),$(calc_goodput $payload $elapsed)" | tee -a "$OUT"
  done

  # ---- sTFTP (secure_dh) ----
  for r in $(seq 1 $RUNS_STFTP); do
    rm -f "$DL_DIR/$f"
    pre=$(read_iface_bytes "$IFACE")
    elapsed=$(time_cmd "python3 tftp_client_secure_psk.py --server '$SERVER' --port $PORT_STFTP --mode secure_dh get '$f' --local '$DL_DIR/$f'")
    post=$(read_iface_bytes "$IFACE"); wire=$((post-pre))
    echo "sTFTP_DH,$f,$payload,$r,$elapsed,$wire,$(calc_overhead $wire $payload),$(calc_goodput $payload $elapsed)" | tee -a "$OUT"
  done

  # ---- SFTP (COLD): prompts password for EACH file (no ControlMaster, no BatchMode) ----
  for r in $(seq 1 $RUNS_SFTP); do
    rm -f "$DL_DIR/$f"
    pre=$(read_iface_bytes "$IFACE")
    elapsed=$(time_cmd "sftp -q -oStrictHostKeyChecking=accept-new -oCompression=no '$SERVER_USER@$SERVER:/home/$SERVER_USER/stftp/files/$f' '$DL_DIR/$f'")
    post=$(read_iface_bytes "$IFACE"); wire=$((post-pre))
    echo "SFTP_cold,$f,$payload,$r,$elapsed,$wire,$(calc_overhead $wire $payload),$(calc_goodput $payload $elapsed)" | tee -a "$OUT"
  done

done

echo "Done -> $OUT"
