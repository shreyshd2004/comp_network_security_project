#!/usr/bin/env bash
set -euo pipefail

SERVER="130.207.114.26"   # shuttle1
PORT_TFTP=6970
PORT_STFTP=6969
FILES=("f_4k.bin" "f_32k.bin" "f_2m.bin")
# hardcoded payload sizes (bytes)
declare -A BYTES=(
  ["f_4k.bin"]=4096
  ["f_32k.bin"]=32768
  ["f_2m.bin"]=2097152
)
RUNS=5

iface_from_route() {
  ip route get "$SERVER" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}
read_iface_bytes() {
  local ifc=$1
  local rx=$(cat /sys/class/net/"$ifc"/statistics/rx_bytes)
  local tx=$(cat /sys/class/net/"$ifc"/statistics/tx_bytes)
  echo $((rx+tx))
}
time_cmd() { /usr/bin/time -p bash -c "$1" 2>&1 | awk '/^real/ {print $2}' || echo "NA"; }

IFACE=$(iface_from_route)
[[ -z "$IFACE" ]] && { echo "Could not resolve interface to $SERVER"; exit 1; }
echo "Using interface: $IFACE"

mkdir -p downloads
OUT="results_min_$(date +%Y%m%d_%H%M%S).csv"
echo "proto,file,bytes,run,elapsed_s,wire_bytes,overhead_pct,goodput_Mbps" > "$OUT"

for f in "${FILES[@]}"; do
  payload=${BYTES[$f]}
  [[ -z "${payload:-}" ]] && { echo "No payload size for $f"; continue; }

  for r in $(seq 1 $RUNS); do
    echo "--- TFTP $f run $r ---"
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
wire=$wire; payload=$payload
print("NA" if $wire==0 else round((wire - payload) * 100.0 / payload, 2))
PY
)
    goodput=$(python3 - <<PY
bits=$payload*8.0
t_str="$elapsed"
try:
    t=float(t_str)
    print(round(bits/t/1e6,3) if t>0 else "NA")
except:
    print("NA")
PY
)
    echo "TFTP,$f,$payload,$r,$elapsed,$wire,$overhead,$goodput" | tee -a "$OUT"

    echo "--- sTFTP_DH $f run $r ---"
    rm -f "downloads/$f"
    pre=$(read_iface_bytes "$IFACE")
    elapsed=$(time_cmd "python3 tftp_client_secure_psk.py --server '$SERVER' --port $PORT_STFTP --mode secure_dh get '$f' --local 'downloads/$f'")
    post=$(read_iface_bytes "$IFACE"); wire=$((post-pre))
    overhead=$(python3 - <<PY
wire=$wire; payload=$payload
print("NA" if $wire==0 else round((wire - payload) * 100.0 / payload, 2))
PY
)
    goodput=$(python3 - <<PY
bits=$payload*8.0
t_str="$elapsed"
try:
    t=float(t_str)
    print(round(bits/t/1e6,3) if t>0 else "NA")
except:
    print("NA")
PY
)
    echo "sTFTP_DH,$f,$payload,$r,$elapsed,$wire,$overhead,$goodput" | tee -a "$OUT"
  done
done

echo "Done -> $OUT"
