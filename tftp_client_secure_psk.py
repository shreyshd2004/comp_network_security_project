#!/usr/bin/env python3
"""
Basic TFTP Client Implementation (+ optional AES-GCM with PSK)
RFC1350-compliant baseline; secure mode encrypts/decrypts DATA using a pre-shared key.
"""

import socket
import struct
import os
import sys
import argparse
from typing import Tuple

# TFTP Opcodes
OPCODE_RRQ = 1    # Read Request
OPCODE_WRQ = 2    # Write Request
OPCODE_DATA = 3   # Data
OPCODE_ACK = 4    # Acknowledgment
OPCODE_ERROR = 5  # Error

# TFTP Error Codes
ERROR_NOT_DEFINED = 0
ERROR_FILE_NOT_FOUND = 1
ERROR_ACCESS_VIOLATION = 2
ERROR_DISK_FULL = 3
ERROR_ILLEGAL_OPERATION = 4
ERROR_UNKNOWN_TID = 5
ERROR_FILE_EXISTS = 6
ERROR_NO_SUCH_USER = 7

# TFTP Constants
DEFAULT_BLOCK_SIZE = 512          # baseline payload size
SECURE_PLAINTEXT_BLOCK = 496      # secure mode plaintext per DATA block (ct+tag ~= 512)
DEFAULT_TIMEOUT = 5
MAX_PACKET_SIZE = 2048  # give some buffer space

# Crypto (optional)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, hmac
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()

def make_nonce(psk: bytes, filename: str, direction: str, block_no: int) -> bytes:
    """
    12-byte GCM nonce derived from (psk, filename, direction, block_no).
    direction: 'dl' for server->client (GET), 'ul' for client->server (PUT)
    """
    ctx = f"{direction}|{filename}|{block_no}".encode('utf-8')
    return hmac_sha256(psk, ctx)[:12]

class TFTPClient:
    def __init__(self, server_host='localhost', server_port=69, mode='baseline', psk_hex=None):
        self.server_host = server_host
        self.server_port = server_port
        self.mode = mode
        self.psk = bytes.fromhex(psk_hex) if (psk_hex and mode == 'secure') else None
        if self.mode == 'secure' and not HAVE_CRYPTO:
            raise SystemExit("cryptography is required for --mode secure. Try: pip install cryptography")
        self.socket = None

    def connect(self):
        """Create UDP socket for TFTP communication"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(DEFAULT_TIMEOUT)

    def disconnect(self):
        """Close the socket"""
        if self.socket:
            self.socket.close()

    def get_file(self, remote_filename: str, local_filename: str = None) -> bool:
        """Download a file from the TFTP server"""
        # fresh socket per transfer (avoid cross-talk)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)

        if local_filename is None:
            local_filename = remote_filename

        try:
            # RRQ: opcode + filename + 0 + "octet" + 0
            rrq_packet = struct.pack('>H', OPCODE_RRQ)
            rrq_packet += remote_filename.encode('ascii') + b'\x00'
            rrq_packet += b'octet\x00'
            sock.sendto(rrq_packet, (self.server_host, self.server_port))

            with open(local_filename, 'wb') as f:
                expected_block = 1
                transfer_addr = None  # will lock on first DATA

                while True:
                    try:
                        data, addr = sock.recvfrom(MAX_PACKET_SIZE)
                    except socket.timeout:
                        # re-send RRQ if still waiting for block 1, else ACK last good
                        if expected_block == 1:
                            sock.sendto(rrq_packet, (self.server_host, self.server_port))
                        else:
                            sock.sendto(struct.pack('>HH', OPCODE_ACK, expected_block - 1), transfer_addr)
                        continue

                    if len(data) < 4:
                        # ignore junk
                        continue

                    opcode, block_num = struct.unpack('>HH', data[:4])

                    if opcode == OPCODE_ERROR:
                        error_code, error_msg = self.parse_error(data)
                        print(f"Server error {error_code}: {error_msg}")
                        return False

                    if opcode != OPCODE_DATA:
                        # ignore unrelated packets
                        continue

                    # Lock to the server's chosen transfer port (TID) on first valid DATA
                    if transfer_addr is None:
                        transfer_addr = addr

                    # Ignore packets from unexpected address
                    if addr != transfer_addr:
                        continue

                    # Ignore out-of-order/duplicate blocks; re-ACK last good to prompt retransmit
                    if block_num != expected_block:
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, max(0, expected_block - 1)), transfer_addr)
                        continue

                    payload = data[4:]

                    if self.mode == 'secure':
                        aes = AESGCM(self.psk)
                        nonce = make_nonce(self.psk, remote_filename, 'dl', block_num)
                        aad = f"{remote_filename}|{block_num}|dl".encode('utf-8')
                        try:
                            file_data = aes.decrypt(nonce, payload, aad)
                        except Exception as e:
                            # Ask for retransmit of last good
                            sock.sendto(struct.pack('>HH', OPCODE_ACK, expected_block - 1), transfer_addr)
                            continue
                        f.write(file_data)
                        # ACK current block
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, block_num), transfer_addr)
                        if len(file_data) < SECURE_PLAINTEXT_BLOCK:
                            break
                    else:
                        f.write(payload)
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, block_num), transfer_addr)
                        if len(payload) < DEFAULT_BLOCK_SIZE:
                            break

                    expected_block += 1

            print(f"File downloaded successfully: {local_filename}")
            return True

        except socket.timeout:
            print("Timeout waiting for server response")
            return False
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
        finally:
            sock.close()

    def put_file(self, local_filename: str, remote_filename: str = None) -> bool:
        """Upload a file to the TFTP server"""
        if remote_filename is None:
            remote_filename = local_filename

        if not os.path.exists(local_filename):
            print(f"Local file not found: {local_filename}")
            return False

        # fresh socket per transfer
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)

        try:
            # WRQ: opcode + filename + 0 + "octet" + 0
            wrq_packet = struct.pack('>H', OPCODE_WRQ)
            wrq_packet += remote_filename.encode('ascii') + b'\x00'
            wrq_packet += b'octet\x00'

            server_addr = (self.server_host, self.server_port)

            # Send WRQ with retry on timeout until we get ACK(0)
            transfer_addr = None
            for _ in range(8):  # up to 8 retries
                sock.sendto(wrq_packet, server_addr)
                try:
                    while True:
                        data, addr = sock.recvfrom(MAX_PACKET_SIZE)
                        if len(data) < 4:
                            continue
                        op, blk = struct.unpack('>HH', data[:4])
                        if op == OPCODE_ERROR:
                            error_code, error_msg = self.parse_error(data)
                            print(f"Server error {error_code}: {error_msg}")
                            return False
                        if op == OPCODE_ACK and blk == 0:
                            transfer_addr = addr  # lock on server's TID
                            break
                        # ignore anything else (e.g., stray DATA), keep waiting until timeout
                    if transfer_addr:
                        break
                except socket.timeout:
                    # retry WRQ
                    continue

            if not transfer_addr:
                print("Timeout waiting for server response")
                return False

            # Send file blocks
            with open(local_filename, 'rb') as f:
                block_num = 1
                while True:
                    pt = f.read(SECURE_PLAINTEXT_BLOCK if self.mode == 'secure' else DEFAULT_BLOCK_SIZE)
                    if pt is None:
                        pt = b''

                    if self.mode == 'secure':
                        aes = AESGCM(self.psk)
                        nonce = make_nonce(self.psk, remote_filename, 'ul', block_num)
                        aad = f"{remote_filename}|{block_num}|ul".encode('utf-8')
                        payload = aes.encrypt(nonce, pt, aad)
                    else:
                        payload = pt

                    packet = struct.pack('>HH', OPCODE_DATA, block_num) + payload

                    # Retry sending each block until we get the matching ACK
                    for _ in range(8):
                        sock.sendto(packet, transfer_addr)
                        try:
                            ack_data, ack_addr = sock.recvfrom(MAX_PACKET_SIZE)
                        except socket.timeout:
                            continue
                        if ack_addr != transfer_addr or len(ack_data) < 4:
                            continue
                        ack_opcode, ack_block = struct.unpack('>HH', ack_data[:4])
                        if ack_opcode == OPCODE_ERROR:
                            error_code, error_msg = self.parse_error(ack_data)
                            print(f"Server error {error_code}: {error_msg}")
                            return False
                        if ack_opcode == OPCODE_ACK and ack_block == block_num:
                            break
                    else:
                        print(f"PUT: giving up on block {block_num}")
                        return False

                    if len(pt) < (SECURE_PLAINTEXT_BLOCK if self.mode=='secure' else DEFAULT_BLOCK_SIZE):
                        break
                    block_num += 1

            # Optional final empty DATA (some servers expect it; our server tolerates either)
            try:
                packet = struct.pack('>HH', OPCODE_DATA, block_num + 1) + b''
                sock.sendto(packet, transfer_addr)
                sock.settimeout(1.0)
                sock.recvfrom(MAX_PACKET_SIZE)  # best-effort final ACK
            except Exception:
                pass

            print(f"File uploaded successfully: {remote_filename}")
            return True

        except socket.timeout:
            print("Timeout waiting for server response")
            return False
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
        finally:
            sock.close()


    def parse_error(self, data: bytes) -> Tuple[int, str]:
        """Parse error packet"""
        try:
            error_code = struct.unpack('>H', data[2:4])[0]
            error_msg = data[4:-1].decode('ascii')  # Remove null terminator
            return error_code, error_msg
        except:
            return ERROR_NOT_DEFINED, "Unknown error"


def main():
    """Main function for TFTP client"""
    parser = argparse.ArgumentParser(description='Basic TFTP Client (+ secure mode)')
    parser.add_argument('--server', default='localhost', help='TFTP server host')
    parser.add_argument('--port', type=int, default=69, help='TFTP server port')
    parser.add_argument('--mode', choices=['baseline','secure'], default='baseline', help='Transfer mode')
    parser.add_argument('--psk', default=None, help='Hex-encoded 32-byte key (AES-256-GCM) for secure mode')
    parser.add_argument('action', choices=['get', 'put'], help='Action: get or put')
    parser.add_argument('filename', help='Filename')
    parser.add_argument('--local', help='Local filename (for put action)')

    args = parser.parse_args()
    if args.mode == 'secure' and not args.psk:
        print("Error: --psk is required for --mode secure")
        sys.exit(1)

    client = TFTPClient(args.server, args.port, args.mode, args.psk)

    try:
        if args.action == 'get':
            success = client.get_file(args.filename, args.local)
        elif args.action == 'put':
            success = client.put_file(args.filename, args.local)

        if not success:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    finally:
        client.disconnect()

if __name__ == '__main__':
    main()
