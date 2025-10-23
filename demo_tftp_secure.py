#!/usr/bin/env python3
"""
Unified TFTP Demo (Baseline + Secure PSK AES-GCM)
- Creates demo files
- Runs baseline demo (server + client)
- Runs secure demo (server + client with PSK)
- Shows downloads, uploads, error handling, and verifies integrity

Usage examples:
  python demo_tftp_secure.py                  # run both demos with defaults
  python demo_tftp_secure.py --only secure    # run only secure
  python demo_tftp_secure.py --only baseline  # run only baseline
  python demo_tftp_secure.py --psk <hexkey>   # set PSK for secure demo
"""

import os
import sys
import time
import subprocess
import signal
import shutil
from pathlib import Path
import argparse
import hashlib

HERE = Path(__file__).resolve().parent
BASELINE_DIR = HERE / "baseline_tftp"
SECURE_CLIENT = HERE / "tftp_client_secure_psk.py"
SECURE_SERVER = HERE / "tftp_server_secure_psk.py"

# Make sure baseline client import works
sys.path.insert(0, str(BASELINE_DIR))
from tftp_client import TFTPClient  # baseline client

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1<<16), b""):
            h.update(chunk)
    return h.hexdigest()

def create_demo_files(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    demo_files = {
        'readme.txt': 'Welcome to the TFTP Demo!\n\nThis is a demonstration of the baseline and secure (AES-GCM with PSK) TFTP implementations.\nTFTP (Trivial File Transfer Protocol) is a simple protocol for transferring files over UDP.\n\nFeatures demonstrated:\n- File downloads (GET)\n- File uploads (PUT)\n- Error handling\n- Binary file transfers\n- Secure mode with authenticated encryption (AES-GCM)\n',
        'config.json': '{\n    "server": {\n        "host": "localhost",\n        "port": 6969,\n        "timeout": 5\n    },\n    "client": {\n        "block_size": 512,\n        "mode": "octet"\n    }\n}',
        'data.bin': bytes([i % 256 for i in range(2048)])  # 2KB test data
    }
    print("Creating demo files...")
    for filename, content in demo_files.items():
        fp = root / filename
        if isinstance(content, str):
            fp.write_text(content)
            size = len(content)
        else:
            fp.write_bytes(content)
            size = len(content)
        print(f"  Created: {fp} ({size} bytes)")

class PopenProc:
    def __init__(self, cmd):
        self.cmd = cmd
        self.p = None
    def start(self):
        self.p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.0)
        if self.p.poll() is not None:
            out, err = self.p.communicate()
            raise RuntimeError(f"Process failed to start.\nCMD: {' '.join(self.cmd)}\nSTDERR:\n{err.decode()}")
        return self
    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.p.kill()
        self.p = None


def start_capture(pcap_file: str, iface: str = 'lo0', bpf: str = 'udp and host 127.0.0.1'):
    """Start tcpdump to write to pcap_file. Returns subprocess.Popen or None on failure."""
    tcpdump = shutil.which('tcpdump')
    if not tcpdump:
        print("tcpdump not found on PATH; skipping packet capture")
        return None

    cmd = [tcpdump, '-i', iface, '-s', '0', '-w', pcap_file, bpf]
    try:
        # Try to start without sudo first (may fail with permission).
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.4)
        if p.poll() is not None:
            # process exited quickly — read stderr and inform user to start tcpdump manually
            _, err = p.communicate()
            print(f"tcpdump failed to start: {err.decode().strip()}")
            print("Permission to capture may be required. Please start tcpdump manually in another terminal, for example:\n")
            example = f"sudo {tcpdump} -i {iface} -s 0 -w {pcap_file} '{bpf}'"
            print(example)
            return None
        print(f"Started packet capture to {pcap_file} (iface={iface})")
        return p
    except Exception as e:
        print(f"Error starting tcpdump: {e}")
        return None


def stop_capture(proc: subprocess.Popen):
    """Stop tcpdump process started by start_capture."""
    if not proc:
        return
    try:
        # Try graceful stop so pcap is flushed
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
    finally:
        print("Stopped packet capture")

def run_baseline_demo(server_root: Path) -> bool:
    print("\n=== Baseline TFTP Demo ===")
    # Start baseline server
    server_script = BASELINE_DIR / "tftp_server.py"
    proc = PopenProc([sys.executable, str(server_script), "--host", "localhost", "--port", "6969", "--root-dir", str(server_root)]).start()
    try:
        client = TFTPClient("localhost", 6969)

        # Downloads
        ok = True
        for name in ["readme.txt", "config.json", "data.bin"]:
            print(f"\n--- Baseline GET {name} ---")
            dst = HERE / f"baseline_downloaded_{name}"
            if dst.exists():
                dst.unlink()
            if client.get_file(name, str(dst)):
                print(f"✓ Downloaded {name}")
            else:
                print(f"✗ Download failed for {name}")
                ok = False

        # Upload
        print("\n--- Baseline PUT upload_readme.txt -> uploaded_readme.txt ---")
        upload_src = server_root / "readme.txt"
        ok_up = client.put_file(str(upload_src), "uploaded_readme.txt")
        print("✓ Upload success" if ok_up else "✗ Upload failed")
        ok = ok and ok_up

        # Error handling
        print("\n--- Baseline Error Handling ---")
        if not client.get_file("no_such_file.txt"):
            print("✓ Handled non-existent file")
        else:
            print("✗ Should have failed for non-existent file")
            ok = False

        if not client.put_file(str(upload_src), "readme.txt"):  # overwrite attempt
            print("✓ Prevented overwrite existing file")
        else:
            print("✗ Should have failed to overwrite existing file")
            ok = False

        # Integrity check for data.bin
        src_hash = sha256_file(server_root / "data.bin")
        dst_hash = sha256_file(HERE / "baseline_downloaded_data.bin")
        if src_hash == dst_hash:
            print(f"✓ Integrity OK for data.bin ({src_hash[:12]}...)")
        else:
            print("✗ Integrity mismatch for data.bin")
            ok = False

        return ok
    finally:
        print("\nStopping baseline server...")
        proc.stop()
        print("✓ Baseline server stopped")

def run_secure_demo(server_root: Path, psk_hex: str) -> bool:
    print("\n=== Secure TFTP Demo (AES-GCM with PSK) ===")
    # Start secure server (subprocess)
    if not SECURE_SERVER.exists() or not SECURE_CLIENT.exists():
        print("Secure scripts not found. Place tftp_server_secure_psk.py and tftp_client_secure_psk.py next to this demo script.")
        return False

    proc = PopenProc([sys.executable, str(SECURE_SERVER), "--host", "localhost", "--port", "6969", "--root-dir", str(server_root),
                      "--mode", "secure", "--psk", psk_hex]).start()
    try:
        # Import secure client module and use it
        import importlib.util
        spec = importlib.util.spec_from_file_location("secure_client_mod", str(SECURE_CLIENT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        SecureClient = getattr(mod, "TFTPClient")

        client = SecureClient("localhost", 6969, mode="secure", psk_hex=psk_hex)

        ok = True
        # Downloads
        for name in ["readme.txt", "config.json", "data.bin"]:
            print(f"\n--- Secure GET {name} ---")
            dst = HERE / f"secure_downloaded_{name}"
            if dst.exists():
                dst.unlink()
            if client.get_file(name, str(dst)):
                print(f"✓ Downloaded {name}")
            else:
                print(f"✗ Download failed for {name}")
                ok = False

        # Upload
        print("\n--- Secure PUT upload_readme.txt -> uploaded_secure_readme.txt ---")
        upload_src = server_root / "readme.txt"
        ok_up = client.put_file(str(upload_src), "uploaded_secure_readme.txt")
        print("✓ Upload success" if ok_up else "✗ Upload failed")
        ok = ok and ok_up

        # Integrity check for data.bin
        src_hash = sha256_file(server_root / "data.bin")
        dst_hash = sha256_file(HERE / "secure_downloaded_data.bin")
        if src_hash == dst_hash:
            print(f"✓ Integrity OK for secure data.bin ({src_hash[:12]}...)")
        else:
            print("✗ Integrity mismatch for secure data.bin")
            ok = False

        return ok
    finally:
        print("\nStopping secure server...")
        proc.stop()
        print("✓ Secure server stopped")

def main():
    ap = argparse.ArgumentParser(description="Unified TFTP Demo (Baseline + Secure PSK)")
    ap.add_argument("--only", choices=["baseline","secure","both"], default="both")
    ap.add_argument("--psk", default="000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
                    help="Hex-encoded 32-byte PSK for secure demo")
    ap.add_argument("--capture-file", default=None, help="If set, start tcpdump and write capture to this pcap file")
    ap.add_argument("--capture-iface", default="lo0", help="Interface to capture on (default lo0)")
    ap.add_argument("--capture-filter", default="udp and host 127.0.0.1", help="BPF filter for tcpdump (default: 'udp and host 127.0.0.1')")
    args = ap.parse_args()

    demo_dir = HERE / "demo_files"
    # Clean old downloads
    for p in list(HERE.glob("baseline_downloaded_*")) + list(HERE.glob("secure_downloaded_*")):
        try:
            p.unlink()
        except Exception:
            pass

    create_demo_files(demo_dir)

    # Optionally start packet capture
    pcap_proc = None
    if args.capture_file:
        pcap_proc = start_capture(args.capture_file, iface=args.capture_iface, bpf=args.capture_filter)

    passed = True
    try:
        if args.only in ("baseline", "both"):
            passed = run_baseline_demo(demo_dir) and passed
        if args.only in ("secure", "both"):
            passed = run_secure_demo(demo_dir, args.psk) and passed
    finally:
        # Ensure capture is stopped and pcap flushed
        if pcap_proc:
            stop_capture(pcap_proc)

    print("\n" + "="*60)
    print(f"DEMO RESULT: {'SUCCESS' if passed else 'FAIL'}")
    print("="*60)
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
