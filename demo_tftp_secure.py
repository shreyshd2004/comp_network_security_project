#!/usr/bin/env python3
"""
Unified TFTP Demo (Baseline + Secure PSK AES-GCM + Secure DH AES-GCM)
- Creates demo files
- Runs baseline demo (server + client)
- Runs secure PSK demo (server + client with static PSK)
- Runs secure DH demo (server + client with dynamic DH key exchange)
- Shows downloads, uploads, error handling, and verifies integrity

Usage examples:
  python demo_tftp_secure.py                     # run all three demos
  python demo_tftp_secure.py --only secure_dh    # run only DH demo
  python demo_tftp_secure.py --only baseline     # run only baseline
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
# --- IMPORTANT: These paths must match the file names from previous responses ---
SECURE_CLIENT = HERE / "tftp_client_secure_psk.py" 
SECURE_SERVER = HERE / "tftp_server_secure_psk.py" 

# Make sure baseline client import works (assuming the baseline is available)
try:
    sys.path.insert(0, str(BASELINE_DIR))
    from tftp_client import TFTPClient  # baseline client class
except ImportError:
    # Fallback to importing from our generated secure client/server files 
    # if the dedicated baseline client isn't available.
    print("Warning: Could not import baseline tftp_client. Falling back to secure implementation.")
    import importlib.util
    spec = importlib.util.spec_from_file_location("secure_client_mod", str(SECURE_CLIENT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    TFTPClient = getattr(mod, "TFTPClient")

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1<<16), b""):
            h.update(chunk)
    return h.hexdigest()

def create_demo_files(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    demo_files = {
        'readme.txt': 'Welcome to the TFTP Demo!\n\nThis is a demonstration of secure TFTP.\n',
        'config.json': '{\n    "version": 1.0\n}',
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

def run_test_suite(client_instance, mode_name: str, server_root: Path, output_prefix: str) -> bool:
    """Runs a standard GET/PUT/Error test suite for a given client mode."""
    ok = True
    
    # Downloads
    for name in ["readme.txt", "config.json", "data.bin"]:
        print(f"\n--- {mode_name} GET {name} ---")
        dst = HERE / f"{output_prefix}_downloaded_{name}"
        if dst.exists(): dst.unlink()
        
        # Use the correct client method (which now uses the mode set on init)
        if client_instance.get_file(name, str(dst)):
            print(f"✓ Downloaded {name}")
        else:
            print(f"✗ Download failed for {name}")
            ok = False

    # Upload
    print(f"\n--- {mode_name} PUT upload_data.bin -> uploaded_{output_prefix}_data.bin ---")
    upload_src = server_root / "data.bin"
    ok_up = client_instance.put_file(str(upload_src), f"uploaded_{output_prefix}_data.bin")
    print("✓ Upload success" if ok_up else "✗ Upload failed")
    ok = ok and ok_up

    # Error handling
    print(f"\n--- {mode_name} Error Handling ---")
    if not client_instance.get_file("no_such_file.txt"):
        print("✓ Handled non-existent file")
    else:
        print("✗ Should have failed for non-existent file")
        ok = False

    # Integrity check for data.bin
    try:
        src_hash = sha256_file(server_root / "data.bin")
        dst_hash = sha256_file(HERE / f"{output_prefix}_downloaded_data.bin")
        if src_hash == dst_hash:
            print(f"✓ Integrity OK for data.bin ({src_hash[:12]}...)")
        else:
            print(f"✗ Integrity mismatch for data.bin. Expected {src_hash}, Got {dst_hash}")
            ok = False
    except FileNotFoundError:
        print(f"✗ Cannot verify integrity, downloaded file {output_prefix}_downloaded_data.bin not found.")
        ok = False
        
    return ok

def run_baseline_demo(server_root: Path) -> bool:
    print("\n" + "="*20 + " Baseline TFTP Demo " + "="*20)
    server_script = HERE / "baseline_tftp" / "tftp_server.py"
    
    # Start baseline server
    proc = PopenProc([sys.executable, str(server_script), "--host", "127.0.0.1", "--port", "6969", "--root-dir", str(server_root)]).start()
    try:
        # Initialize baseline client
        client = TFTPClient("127.0.0.1", 6969, mode="baseline")
        result = run_test_suite(client, "Baseline", server_root, "baseline")
        return result
    finally:
        print("\nStopping baseline server...")
        proc.stop()
        print("✓ Baseline server stopped")

def run_psk_demo(server_root: Path, psk_hex: str) -> bool:
    print("\n" + "="*20 + " Secure TFTP Demo (PSK) " + "="*20)
    if not SECURE_SERVER.exists() or not SECURE_CLIENT.exists():
        print("Secure scripts not found.")
        return False
        
    # Server command (MUST pass the PSK)
    server_cmd = [
        sys.executable, str(SECURE_SERVER), 
        "--host", "127.0.0.1", "--port", "6969", 
        "--root-dir", str(server_root),
        "--mode", "secure",
        "--psk", psk_hex
    ]
    proc = PopenProc(server_cmd).start()
    
    try:
        # Import the secure client class
        import importlib.util
        spec = importlib.util.spec_from_file_location("secure_client_mod", str(SECURE_CLIENT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        SecureClient = getattr(mod, "TFTPClient")

        # Initialize secure client (MUST pass the PSK)
        client = SecureClient("127.0.0.1", 6969, mode="secure", psk_hex=psk_hex)
        result = run_test_suite(client, "Secure-PSK", server_root, "secure_psk")
        return result
    finally:
        print("\nStopping PSK server...")
        proc.stop()
        print("✓ PSK server stopped")

def run_dh_demo(server_root: Path) -> bool:
    print("\n" + "="*20 + " Secure TFTP Demo (DH) " + "="*20)
    if not SECURE_SERVER.exists() or not SECURE_CLIENT.exists():
        print("Secure DH scripts not found.")
        return False
        
    # Server command (Uses DH mode, NO PSK required)
    server_cmd = [
        sys.executable, str(SECURE_SERVER), 
        "--host", "127.0.0.1", "--port", "6969", 
        "--root-dir", str(server_root),
        "--mode", "secure_dh"
    ]
    proc = PopenProc(server_cmd).start()
    
    try:
        # Import the secure client class
        import importlib.util
        spec = importlib.util.spec_from_file_location("secure_client_mod", str(SECURE_CLIENT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        SecureClient = getattr(mod, "TFTPClient")

        # Initialize DH client (Uses DH mode, NO PSK required)
        client = SecureClient("127.0.0.1", 6969, mode="secure_dh")
        result = run_test_suite(client, "Secure-DH", server_root, "secure_dh")
        return result
    finally:
        print("\nStopping DH server...")
        proc.stop()
        print("✓ DH server stopped")


def main():
    ap = argparse.ArgumentParser(description="Unified TFTP Demo (Baseline + Secure PSK + Secure DH)")
    ap.add_argument("--only", choices=["baseline", "secure_psk", "secure_dh", "all"], default="all",
                    help="Choose which demo(s) to run.")
    ap.add_argument("--psk", default="000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
                    help="Hex-encoded 32-byte PSK for secure_psk demo")
    args = ap.parse_args()

    demo_dir = HERE / "demo_files"
    
    # Clean old download files and uploaded files
    for p in list(HERE.glob("*_downloaded_*")) + list(demo_dir.glob("uploaded_*")):
        try:
            p.unlink()
        except Exception:
            pass

    create_demo_files(demo_dir)

    passed = True
    
    try:
        if args.only in ("baseline", "all"):
            passed = run_baseline_demo(demo_dir) and passed
            
        if args.only in ("secure_psk", "all"):
            passed = run_psk_demo(demo_dir, args.psk) and passed
            
        if args.only in ("secure_dh", "all"):
            passed = run_dh_demo(demo_dir) and passed
            
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
        passed = False
    finally:
        # Stop any lingering processes (PopenProc instances handle this locally now)
        pass

    print("\n" + "="*60)
    print(f"DEMO RESULT: {'SUCCESS' if passed else 'FAIL'}")
    print("="*60)
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())

