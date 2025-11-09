#!/usr/bin/env python3
"""
Unified TFTP Demo (Baseline + Secure PSK/DH)
- Creates demo files
- Runs baseline demo (server + client)
- Runs secure demo (PSK and DH modes)
- Shows downloads, uploads, error handling, and verifies integrity

Usage examples:
  python demo_tftp_secure.py                  # run both PSK and DH demos with defaults
  python demo_tftp_secure.py --only secure_psk # run only secure PSK
  python demo_tftp_secure.py --only secure_dh # run only secure DH
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

# Make sure baseline client import works (assuming baseline is just a copy of the main code without crypto features)
try:
    sys.path.insert(0, str(BASELINE_DIR))
    from tftp_client import TFTPClient  # baseline client
except ImportError:
    # If the import fails, fall back to using the main script file
    print("Warning: Could not import baseline client. Relying on main tftp_client.py.")
    pass

def sha256_file(p: Path):
    """Calculates the SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1<<16), b""):
            h.update(chunk)
    return h.hexdigest()

def create_demo_files(root: Path) -> None:
    """Creates dummy files for testing in the root directory."""
    root.mkdir(parents=True, exist_ok=True)
    demo_files = {
        'readme.txt': 'Welcome to the TFTP Demo!\n\nThis is a demonstration of the baseline and secure (AES-GCM with PSK/DH) TFTP implementations.\n\nFeatures demonstrated:\n- File downloads (GET)\n- File uploads (PUT)\n- Secure mode with authenticated encryption (AES-GCM)\n- Diffie-Hellman Key Exchange (DH) mode\n',
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
    """Simple wrapper for subprocess.Popen to handle server startup/teardown."""
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


# --- Helper functions for optional packet capture omitted for brevity ---

# Helper function to get the client class instance
def get_tftp_client(mode: str, psk_hex: str = None):
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("tftp_mod", str(SECURE_CLIENT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        TFTPClientClass = getattr(mod, "TFTPClient")
        return TFTPClientClass("localhost", 6969, mode=mode, psk_hex=psk_hex)
    except Exception as e:
        print(f"Error loading client class: {e}")
        return None

def run_tftp_test(client, test_name: str, server_root: Path, client_root: Path) -> bool:
    """Runs a standard suite of GET/PUT/Error tests for a given client mode."""
    
    if client is None:
        print(f"Skipping {test_name}: Client initialization failed.")
        return False
        
    ok = True
    
    # --- Downloads (GET) ---
    for name in ["readme.txt", "config.json", "data.bin"]:
        print(f"\n--- {test_name} GET {name} ---")
        dst = client_root / f"{test_name.lower().replace(' ', '_')}_downloaded_{name}"
        if dst.exists():
            dst.unlink()
        if client.get_file(name, str(dst)):
            print(f"✓ Downloaded {name}")
        else:
            print(f"✗ Download failed for {name}")
            ok = False

    # --- Upload (PUT) ---
    print(f"\n--- {test_name} PUT data.bin -> uploaded_{test_name.lower().replace(' ', '_')}_data.bin ---")
    upload_src = f"{test_name.lower().replace(' ', '_')}_downloaded_data.bin"
    remote_name = f"uploaded_{test_name.lower().replace(' ', '_')}_data.bin"

    print(f"Client file {upload_src}; Remote name: {remote_name}")

    ok_up = client.put_file(str(upload_src), remote_name)
    print("✓ Upload success" if ok_up else "✗ Upload failed")
    ok = ok and ok_up

    # --- Error handling ---
    print(f"\n--- {test_name} Error Handling ---")
    if not client.get_file("no_such_file.txt"):
        print("✓ Handled non-existent file")
    else:
        print("✗ Should have failed for non-existent file")
        ok = False

    # --- Integrity check for data.bin ---
    src_hash = sha256_file(server_root / "data.bin")
    dst_path = client_root / f"{test_name.lower().replace(' ', '_')}_downloaded_data.bin"
    if dst_path.exists():
        dst_hash = sha256_file(dst_path)
        if src_hash == dst_hash:
            print(f"✓ Integrity OK for data.bin ({src_hash[:12]}...)")
        else:
            print("✗ Integrity mismatch for data.bin")
            ok = False
    else:
        print("✗ Integrity check skipped (data.bin download failed)")
        ok = False

    return ok


def run_secure_demo(server_root: Path, psk_hex: str, client_root: Path) -> bool:
    print("\n=== Secure TFTP Demo (AES-GCM with PSK) ===")
    
    # Start secure server in PSK mode
    proc = PopenProc([sys.executable, str(SECURE_SERVER), "--host", "localhost", "--port", "6969", "--root-dir", str(server_root),
                      "--mode", "secure", "--psk", psk_hex]).start()
    try:
        client = get_tftp_client("secure", psk_hex)
        return run_tftp_test(client, "Secure PSK", server_root, client_root)
    finally:
        print("\nStopping Secure PSK server...")
        proc.stop()
        print("✓ Secure PSK server stopped")

def run_secure_dh_demo(server_root: Path, client_root: Path) -> bool:
    print("\n=== Secure TFTP Demo (AES-GCM with DH) ===")
    
    # Start secure server in DH mode
    proc = PopenProc([sys.executable, str(SECURE_SERVER), "--host", "localhost", "--port", "6969", "--root-dir", str(server_root),
                      "--mode", "secure_dh"]).start()
    try:
        # Note: PSK is None, as the key is negotiated via DH
        client = get_tftp_client("secure_dh", psk_hex=None) 
        return run_tftp_test(client, "Secure DH", server_root, client_root)
    finally:
        print("\nStopping Secure DH server...")
        proc.stop()
        print("✓ Secure DH server stopped")


def run_baseline_demo(server_root: Path, client_root: Path) -> bool:
    print("\n=== Baseline TFTP Demo ===")
    # Start baseline server
    server_script = BASELINE_DIR / "tftp_server.py"
    proc = PopenProc([sys.executable, str(server_script), "--host", "localhost", "--port", "6969", "--root-dir", str(server_root), "--mode", "baseline"]).start()
    try:
        client = get_tftp_client("baseline")
        return run_tftp_test(client, "Baseline", server_root, client_root)
    finally:
        print("\nStopping baseline server...")
        proc.stop()
        print("✓ Baseline server stopped")


def main():
    ap = argparse.ArgumentParser(description="Unified TFTP Demo (Baseline + Secure PSK/DH)")
    ap.add_argument("--only", choices=["baseline", "secure_psk", "secure_dh", "all"], default="all")
    ap.add_argument("--psk", default="000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
                      help="Hex-encoded 32-byte PSK for secure PSK demo")
    ap.add_argument("--capture-file", default=None, help="If set, start tcpdump and write capture to this pcap file")
    ap.add_argument("--capture-iface", default="lo0", help="Interface to capture on (default lo0)")
    ap.add_argument("--capture-filter", default="udp and host 127.0.0.1", help="BPF filter for tcpdump")
    args = ap.parse_args()

    demo_dir = HERE / "demo_files"
    client_root = HERE # Downloads go here
    
    # Clean old download files
    for p in list(HERE.glob("*_downloaded_*")) + list(HERE.glob("uploaded_*")):
        try:
            if p.is_file():
                p.unlink()
        except Exception:
            pass

    create_demo_files(demo_dir)

    # Optionally start packet capture (omitted implementation details for brevity)
    pcap_proc = None
    # if args.capture_file:
    #    pcap_proc = start_capture(args.capture_file, iface=args.capture_iface, bpf=args.capture_filter)

    passed = True
    try:
        if args.only in ("baseline", "all"):
            passed = run_baseline_demo(demo_dir, client_root) and passed
            
        if args.only in ("secure_psk", "all"):
            passed = run_secure_demo(demo_dir, args.psk, client_root) and passed
            
        if args.only in ("secure_dh", "all"):
            # DH requires a clean slate as it uses the same port
            passed = run_secure_dh_demo(demo_dir, client_root) and passed
            
    finally:
        # Ensure capture is stopped and pcap flushed
        if pcap_proc:
            # stop_capture(pcap_proc)
            pass

    print("\n" + "="*60)
    print(f"DEMO RESULT: {'SUCCESS' if passed else 'FAIL'}")
    print("="*60)
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
