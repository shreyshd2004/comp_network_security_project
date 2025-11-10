#!/usr/bin/env bash
set -euo pipefail

SERVER="130.207.114.26"   # shuttle1
PORT_TFTP=6970
PORT_STFTP=6969
FILES=("f_4k.bin" "f_32k.bin" "f_2m.bin")
RUNS=5
LOCAL_DIR="./files"       # we read payload sizes locally (shared home)

iface_from_route() {
  ip route get "$SERVER" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}
read_iface_bytes() {
  local ifc=$1
  local rx=$(cat /sys/class/net/"$ifc"/statistics/rx_bytes)
  local tx=$(cat /sys/class/net/"$ifc"/statistics/tx_bytes)
  echo $((rx+tx))
}
time_cmd() { /usr/bin/time -p bash -c "$1" 2>&1 | awk '/^real/ {print $2}'; }

# figure out egress iface
IFACE=$(iface_from_route)
[[ -z "$IFACE" ]] && { echo "Could not resolve interface to $SERVER"; exit 1; }
echo "Using interface: $IFACE"

mkdir -p downloads
OUT="results_min_$(date +%Y%m%d_%H%M%S).csv"
echo "proto,file,bytes,run,elapsed_s,wire_bytes,overhead_pct,goodput_Mbps" > "$OUT"

for f in "${FILES[@]}"; do
  # payload bytes from local (shared home) copy
  BYTES=$(stat -c%s "$LOCAL_DIR/$f")
  [[ -z "$BYTES" || "$BYTES" = "0" ]] && { echo "Missing $LOCAL_DIR/$f"; exit 1; }

  for r in $(seq 1 $RUNS); do
    # --- TFTP ---
    rm -f "downloads/$f"
    pre=$(read_iface_bytes "$IFACE")
    elapsed=$(time_cmd "python3 - <<PY
from tftpy import TftpClient
c = TftpClient('$SERVER', $PORT_TFTP)
c.download('$f', 'downloads/$f')
PY
")
    post=$(read_iface_bytes "$IFACE"); wire=$((post-pre))
    overhead=$(python3 - <<PY
wire=$wire; payload=$BYTES
print(round((wire - payload) * 100.0 / payload, 2))
PY
)
    goodput=$(python3 - <<PY
bits=$BYTES*8.0; t=float("$elapsed")
print(round(bits/t/1e6,3) if t>0 else "NA")
PY
)
    echo "TFTP,$f,$BYTES,$r,$elapsed,$wire,$overhead,$goodput" | tee -a "$OUT"

    # --- sTFTP (secure_dh) ---
    rm -f "downloads/$f"
    pre=$(read_iface_bytes "$IFACE")
    elapsed=$(time_cmd "python3 tftp_client_secure_psk.py --server '$SERVER' --port $PORT_STFTP --mode secure_dh get '$f' --local 'downloads/$f'")
    post=$(read_iface_bytes "$IFACE"); wire=$((post-pre))
    overhead=$(python3 - <<PY
wire=$wire; payload=$BYTES
print(round((wire - payload) * 100.0 / payload, 2))
PY
)
    goodput=$(python3 - <<PY
bits=$BYTES*8.0; t=float("$elapsed")
print(round(bits/t/1e6,3) if t>0 else "NA")
PY
)
    echo "sTFTP_DH,$f,$BYTES,$r,$elapsed,$wire,$overhead,$goodput" | tee -a "$OUT"

  done
done

echo "Done -> $OUT"
