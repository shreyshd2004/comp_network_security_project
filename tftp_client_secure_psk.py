#!/usr/bin/env python3
"""
Basic TFTP Client Implementation (+ optional AES-GCM with PSK/DH)
RFC1350-compliant baseline; secure mode encrypts/decrypts DATA using a pre-shared key or DH-derived session key.
"""

import socket
import struct
import os
import sys
import argparse
import time
from typing import Tuple, Optional

# TFTP Opcodes
OPCODE_RRQ = 1     # Read Request
OPCODE_WRQ = 2     # Write Request
OPCODE_DATA = 3    # Data
OPCODE_ACK = 4     # Acknowledgment
OPCODE_ERROR = 5   # Error
OPCODE_DH_KEY = 6  # Diffie-Hellman Public Key Exchange

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
DEFAULT_BLOCK_SIZE = 512           # baseline payload size
SECURE_PLAINTEXT_BLOCK = 496       # secure mode plaintext per DATA block (ct+tag ~= 512)
DEFAULT_TIMEOUT = 5
MAX_PACKET_SIZE = 4 + DEFAULT_BLOCK_SIZE + 16 # Add space for GCM tag

# --- Diffie-Hellman Constants ---
# Standardized 2048-bit prime (Group 14)
DH_P_HEX = (
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08'
    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B'
    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A'
    '637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649'
    '286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD2'
    '4CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C'
    '354E4ABC9804F1746C08CA18217C32905E462E36CE3A3348806EC1CDB'
    '19B27A9B79EEA5D4D5460E7941CB5C9778DDC432DAFD3E7356ECFD132'
    '20CC51F2D6BEE9487DA452E2080000000000009941'
)
DH_PRIME_P = int(DH_P_HEX, 16)
DH_GENERATOR_G = 2
DH_PUBLIC_KEY_SIZE= 256 # 2048 bits / 8 bytes


# Crypto (mandatory for secure modes)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

# --- Diffie-Hellman Constants ---
# CRITICAL FIX: Manually define the standardized 2048-bit prime (Group 14) for older library versions.
DH_P_HEX = (
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08'
    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B'
    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A'
    '637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649'
    '286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD2'
    '4CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C'
    '354E4ABC9804F1746C08CA18217C32905E462E36CE3A3348806EC1CDB'
    '19B27A9B79EEA5D4D5460E7941CB5C9778DDC432DAFD3E7356ECFD132'
    '20CC51F2D6BEE9487DA452E2080000000000009941'
)
DH_P = int(DH_P_HEX, 16)
DH_G = 2
DH_KEY_SIZE = 256 # 2048 bits / 8 bytes

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """Computes HMAC-SHA256."""
    h = hmac.HMAC(key, hashes.SHA256(), default_backend())
    h.update(msg)
    return h.finalize()

def make_nonce(shared_key: bytes, filename: str, direction: str, block_no: int) -> bytes:
    """
    12-byte GCM nonce derived from (shared_key, filename, direction, block_no).
    direction: 'dl' for server->client (GET), 'ul' for client->server (PUT)
    """
    ctx = f"{direction}|{filename}|{block_no}".encode('utf-8')
    return hmac_sha256(shared_key, ctx)[:12]

class TFTPClient:
    def __init__(self, server_host='localhost', server_port=69, mode='baseline', psk_hex=None):
        self.server_host = server_host
        self.server_port = server_port
        self.mode = mode
        self.psk = bytes.fromhex(psk_hex) if (psk_hex and mode == 'secure') else None
        self.session_key = None
        
        if self.mode in ['secure', 'secure_dh'] and not HAVE_CRYPTO:
            raise SystemExit("cryptography is required for secure modes. Try: pip install cryptography")
        
        self.socket = None
        self.dh_params = None
        if self.mode == 'secure_dh' and HAVE_CRYPTO:
            try:
                self.dh_params = dh.DHParameterNumbers(DH_PRIME_P, DH_GENERATOR_G).parameters(backend=None)
            except Exception as e:
                # Fallback check for systems where parameters() needs DHParameterNumbers
                try:
                    self.dh_params = dh.generate_parameters(generator=DH_GENERATOR_G, key_size=2048, backend=None)
                except Exception:
                    raise SystemExit(f"Failed to create DH parameters: {e}")

    def connect(self):
        """Create UDP socket for TFTP communication"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(DEFAULT_TIMEOUT)

    def disconnect(self):
        """Close the socket"""
        if self.socket:
            self.socket.close()

    def _generate_dh_keys_client(self) -> Tuple[dh.DHPrivateKey, bytes]:
        """Generates client's DH key pair and returns the private key and RAW public key bytes."""
        private_key = self.dh_params.generate_private_key()
        pub_key = private_key.public_key()
        
        # Serialize the public number (Y) as a fixed-size byte string
        public_key_bytes = pub_key.public_numbers().y.to_bytes(DH_PUBLIC_KEY_SIZE, 'big')
        return private_key, public_key_bytes

    def _derive_shared_secret(self, client_private_key: dh.DHPrivateKey, peer_public_key_bytes: bytes, salt: bytes) -> bytes:
        """Derives the 32-byte AES key using HKDF from the DH shared secret."""
        try:
            # Deserialize the peer's raw public number (Y)
            peer_public_numbers = dh.DHPublicNumbers(
                int.from_bytes(peer_public_key_bytes, 'big'),
                client_private_key.parameters().parameter_numbers() # Use params from client's private key
            )
            peer_public_key = peer_public_numbers.public_key()
            
            # Perform DH key agreement
            shared_secret = client_private_key.exchange(peer_public_key)

            # HKDF to derive a strong 32-byte AES key
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'tftp-dh-key-derivation'
            ).derive(shared_secret)
            
            return key
        except Exception as e:
            raise RuntimeError(f"Error computing shared key: {e}")


    def _handle_dh_key_exchange(self, data: bytes, addr: Tuple[str, int], remote_filename: str) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """
        Handle the DH Key exchange step, triggered by receiving the server's public key (S_PUB).
        Returns (c_pub_packet_bytes, server_tid_addr) or None on failure.
        """
        print(f"Received Server DH Key from {addr[0]}:{addr[1]}. Deriving shared secret...")
        
        # 1. Generate Client DH Key Pair
        client_private_key, client_public_key_bytes = self._generate_dh_keys_client()

        # 2. Extract Server Public Key
        # The DH packet format is 2 bytes opcode + 256 bytes key
        if len(data) < 2 + DH_PUBLIC_KEY_SIZE:
             print("DH key packet too short.")
             return None
        
        server_public_key_bytes = data[2:]
        if len(server_public_key_bytes) != DH_PUBLIC_KEY_SIZE:
             print("DH key size mismatch.")
             return None

        # 3. Derive Shared Key using C_PUB as salt/context (MUST MATCH SERVER)
        shared_key = self._derive_shared_secret(
            client_private_key, 
            server_public_key_bytes, 
            client_public_key_bytes # Use C_PUB as salt to match server implementation
        )
        
        self.session_key = shared_key
        print("Derived Shared Key (AES-256) successfully.")

        # 4. Create Client Public Key (C_PUB) packet to send back
        c_pub_packet = struct.pack('>H', OPCODE_DH_KEY) + client_public_key_bytes

        # The server's TID is established as the source address of this packet.
        server_tid_addr = addr
        return c_pub_packet, server_tid_addr


    def get_file(self, remote_filename: str, local_filename: str = None) -> bool:
        """Download a file from the TFTP server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        if local_filename is None: local_filename = remote_filename
        server_initial_addr = (self.server_host, self.server_port)
        transfer_addr = None
        self.shared_key = None
        rrq_packet = struct.pack('>H', OPCODE_RRQ) + remote_filename.encode('ascii') + b'\x00' + b'octet\x00'
        
        try:
            # 1. Send initial RRQ (retry loop for handshake initiation)
            initial_data, initial_addr = b'', None
            for _ in range(20): # INCREASED RETRY COUNT FOR ROBUST DH INITIATION
                sock.sendto(rrq_packet, server_initial_addr)
                try:
                    initial_data, initial_addr = sock.recvfrom(MAX_PACKET_SIZE)
                    # Check if the response came from a new TID (the transfer socket)
                    if initial_addr[1] != self.server_port: 
                        break
                    # Ignore packets from the initial server port after the first send
                except socket.timeout:
                    continue
            else:
                print("Timeout waiting for server to initiate transfer or DH exchange.")
                return False

            with open(local_filename, 'wb') as f:
                expected_block = 1
                transfer_addr = None  # will lock on first DATA or DH_KEY

            with open(local_filename, 'wb') as f:
                while True:
                    try:
                        data, addr = sock.recvfrom(MAX_PACKET_SIZE)
                    except socket.timeout:
                        # Re-send RRQ if still waiting for block 1 AND TID is not set
                        if expected_block == 1 and transfer_addr is None:
                            sock.sendto(rrq_packet, (self.server_host, self.server_port))
                        elif transfer_addr is not None:
                             # Re-ACK the last good block to prompt retransmit
                            sock.sendto(struct.pack('>HH', OPCODE_ACK, expected_block - 1), transfer_addr)
                        else:
                            # Re-ACK to the original port if DH hasn't finished (less common)
                            sock.sendto(struct.pack('>HH', OPCODE_ACK, max(0, expected_block - 1)), (self.server_host, self.server_port))
                        continue

                    if len(data) < 4:
                        continue

                    opcode, block_num = struct.unpack('>HH', data[:4])

                    if opcode == OPCODE_ERROR:
                        error_code, error_msg = self._parse_error(data)
                        print(f"Server error {error_code}: {error_msg}")
                        return False

                    # FIX: Handle DH Key Exchange before checking for DATA, and lock the TID
                    if opcode == OPCODE_DH_KEY and self.mode == 'secure_dh' and not self.session_key:
                        if HAVE_CRYPTO:
                            dh_result = self._handle_dh_key_exchange(data, addr, remote_filename)
                            
                            if dh_result:
                                c_pub_packet, transfer_addr = dh_result
                                print(f"Sending C_PUB back to server TID: {transfer_addr[1]}")
                                # Send C_PUB response multiple times for robustness
                                for _ in range(3):
                                    sock.sendto(c_pub_packet, transfer_addr)
                                    time.sleep(0.3)
                            else:
                                print("DH Key Exchange failed.")
                                return False
                        continue # Skip to next recv, this packet was DH, not DATA

                    if opcode != OPCODE_DATA:
                        # ignore unrelated packets
                        continue

                    # Lock to the server's chosen transfer port (TID) on first valid DATA
                    # This is the crucial step for baseline and PSK modes.
                    if transfer_addr is None:
                        transfer_addr = addr
                        print(f"Transfer TID locked to {transfer_addr[0]}:{transfer_addr[1]}")

                    # Ignore packets from unexpected address
                    if addr != transfer_addr:
                        # Send an ERROR packet back if we receive data from the WRONG TID
                        error_packet = struct.pack('>HH', OPCODE_ERROR, ERROR_UNKNOWN_TID) + b'Unknown TID\x00'
                        sock.sendto(error_packet, addr)
                        continue

                    # Ignore out-of-order/duplicate blocks; re-ACK last good to prompt retransmit
                    if block_num != expected_block:
                        # Ignore out-of-order/duplicate blocks; re-ACK last good
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, max(0, expected_block - 1)), transfer_addr)
                        continue

                    payload = data[4:]

                    if self.mode in ['secure', 'secure_dh']:
                        session_key = self.session_key if self.session_key else self.psk
                        aes = AESGCM(session_key)
                        nonce = make_nonce(session_key, remote_filename, 'dl', block_num)
                        aad = f"{remote_filename}|{block_num}|dl".encode('utf-8')
                        try:
                            file_data = aes.decrypt(nonce, payload, aad)
                        except Exception as e:
                            # Send ACK for the last successful block to trigger retransmit
                            print(f"Decryption failed for block {block_num}: {e}. Retrying.")
                            sock.sendto(struct.pack('>HH', OPCODE_ACK, expected_block - 1), transfer_addr)
                            continue
                        
                        f.write(file_data)
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, block_num), transfer_addr)
                        # print(f"ACK: {block_num}")
                        if len(file_data) < SECURE_PLAINTEXT_BLOCK:
                            break
                    else:
                        f.write(payload)
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, block_num), transfer_addr)
                        if len(payload) < DEFAULT_BLOCK_SIZE: break

                    expected_block += 1

            print(f"File downloaded successfully: {local_filename}")
            return True

        except socket.timeout:
            print("Timeout waiting for server response")
            return False
        except RuntimeError as e:
             # Catch explicit DH failure from _derive_shared_secret
            print(f"Error downloading file: {e}")
            return False
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
        finally:
            sock.close()
            self.session_key = None

    def put_file(self, local_filename: str, remote_filename: str = None) -> bool:
        """Upload a file to the TFTP server"""
        WRQ_RETRIES = 5
        if remote_filename is None:
            remote_filename = local_filename

        if not os.path.exists(local_filename):
            print(f"Local file not found: {local_filename}")
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        server_initial_addr = (self.server_host, self.server_port)
        transfer_addr = None
        self.shared_key = None
        
        wrq_packet = struct.pack('>H', OPCODE_WRQ) + remote_filename.encode('ascii') + b'\x00' + b'octet\x00'
        
        try:
            # WRQ: opcode + filename + 0 + "octet" + 0
            wrq_packet = struct.pack('>H', OPCODE_WRQ)
            wrq_packet += remote_filename.encode('ascii') + b'\x00'
            wrq_packet += b'octet\x00'

            server_addr = (self.server_host, self.server_port)

            # Send WRQ with retry on timeout until we get ACK(0)
            transfer_addr = None
            for _ in range(WRQ_RETRIES):  # retries
                print("Sending WRQ packet")
                sock.sendto(wrq_packet, server_addr)
                try:
                    while True:
                        data, addr = sock.recvfrom(MAX_PACKET_SIZE)
                        if len(data) < 4:
                            continue
                        op, blk = struct.unpack('>HH', data[:4])
                        print(f"Got a packet: {op}")
                        
                        if op == OPCODE_DH_KEY and self.mode == 'secure_dh' and self.session_key is None:
                            # Handle DH Key exchange initiated by the server upon WRQ
                            dh_result = self._handle_dh_key_exchange(data, addr, remote_filename)
                            if dh_result:
                                c_pub_packet, transfer_addr = dh_result # Set TID here
                                print(f"Sending C_PUB back to server TID: {transfer_addr[1]}")
                                # Send C_PUB response multiple times for robustness
                                for i in range(3):
                                    sock.sendto(c_pub_packet, transfer_addr)
                                    time.sleep(0.3)
                            else:
                                print("DH Key Exchange failed.")
                                return False
                            continue # Wait for the next packet (which should be the ACK 0)

                        if op == OPCODE_ERROR:
                            error_code, error_msg = self.parse_error(data)
                            print(f"Server error {error_code}: {error_msg}")
                            return False
                        if op == OPCODE_ACK and blk == 0:
                            if transfer_addr is None:
                                transfer_addr = addr  # lock on server's TID if not already set by DH
                            break
                        # ignore anything else (e.g., stray DATA), keep waiting until timeout
                    if transfer_addr:
                        break
                except socket.timeout:
                    continue
            else:
                print("Timeout waiting for server to initiate transfer or DH exchange.")
                return False

            # 2. Perform DH exchange if necessary
            if self.mode == 'secure_dh':
                result = self._perform_dh_key_exchange(sock, initial_data, initial_addr)
                if not result: return False
                self.shared_key, transfer_addr = result
                # After DH, we expect ACK(0) next.
                current_ack_block = 0 
                initial_data = b''
            else:
                transfer_addr = initial_addr
                # For baseline/PSK, we expect ACK(0) here
                op, blk = struct.unpack('>HH', initial_data[:4])
                if op == OPCODE_ERROR:
                    error_code, error_msg = self._parse_error(initial_data)
                    print(f"Server error {error_code}: {error_msg}")
                    return False
                if op != OPCODE_ACK or blk != 0:
                    print(f"Expected ACK 0, got {op} {blk}")
                    return False
                current_ack_block = 0
                initial_data = b'' # consumed initial ACK

            # 3. Send file blocks
            with open(local_filename, 'rb') as f:
                block_num = 1
                transfer_key = self.shared_key if self.mode == 'secure_dh' else self.psk
                
                while True:
                    pt = f.read(SECURE_PLAINTEXT_BLOCK if self.mode in ['secure', 'secure_dh'] else DEFAULT_BLOCK_SIZE)
                    if pt is None:
                        pt = b''

                    if self.mode in ['secure', 'secure_dh']:
                        session_key = self.session_key if self.session_key else self.psk
                        aes = AESGCM(session_key)
                        
                        # FIX 1: Change 'dl' to 'ul' for upload nonce generation
                        nonce = make_nonce(session_key, remote_filename, 'ul', block_num)
                        
                        # FIX 2: Correct AAD direction to 'ul' for upload
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
                        
                        # Only accept ACKs from the established TID
                        if ack_addr != transfer_addr or len(ack_data) < 4:
                            continue
                            
                        ack_opcode, ack_block = struct.unpack('>HH', ack_data[:4])
                        if ack_opcode == OPCODE_ERROR:
                            error_code, error_msg = self._parse_error(ack_data)
                            print(f"Server error {error_code}: {error_msg}")
                            return False
                        
                        if ack_opcode == OPCODE_ACK and ack_block == block_num:
                            break
                    else:
                        print(f"PUT: giving up on block {block_num}")
                        return False

                    if len(pt) < (SECURE_PLAINTEXT_BLOCK if self.mode in ['secure', 'secure_dh'] else DEFAULT_BLOCK_SIZE):
                        break
                    block_num += 1

            # Optional final empty DATA (best-effort final ACK)
            try:
                packet = struct.pack('>HH', OPCODE_DATA, block_num + 1) + b''
                sock.sendto(packet, transfer_addr)
                sock.settimeout(1.0)
                sock.recvfrom(MAX_PACKET_SIZE) 
            except Exception:
                pass

            print(f"File uploaded successfully: {remote_filename}")
            return True

        except socket.timeout:
            print("Timeout waiting for server response")
            return False
        except RuntimeError as e:
             # Catch explicit DH failure from _derive_shared_secret
            print(f"Error uploading file: {e}")
            return False
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
        finally:
            sock.close()
            self.session_key = None


def main():
    """Main function for TFTP client"""
    parser = argparse.ArgumentParser(description='Secure TFTP Client (PSK + DH)')
    parser.add_argument('--server', default='localhost', help='TFTP server host')
    parser.add_argument('--port', type=int, default=69, help='TFTP server port')
    parser.add_argument('--mode', choices=['baseline','secure', 'secure_dh'], default='baseline', help='Transfer mode')
    parser.add_argument('--psk', default=None, help='Hex-encoded 32-byte key (AES-256-GCM) for secure mode')
    parser.add_argument('action', choices=['get', 'put'], help='Action: get or put')
    parser.add_argument('filename', help='Filename')
    parser.add_argument('--local', help='Local filename (for put action)')

    args = parser.parse_args()
    if args.mode == 'secure' and not args.psk:
        print("Error: --psk is required for --mode secure")
        sys.exit(1)
    if args.mode == 'secure_dh' and not HAVE_CRYPTO:
        print("Error: DH mode requires the cryptography library.")
        sys.exit(1)

    # Use port 6969 in the demo environment for consistency
    port = args.port if args.port != 69 else 6969
    client = TFTPClient(args.server, port, args.mode, args.psk)

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

