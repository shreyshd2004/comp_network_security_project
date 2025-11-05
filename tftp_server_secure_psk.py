#!/usr/bin/env python3
"""
Simplified TFTP Server Implementation (+ DH Key Exchange & AES-GCM)
Handles one request at a time. Supports baseline, PSK secure, and DH key exchange secure modes.
"""

import socket
import struct
import os
import sys
import argparse
from typing import Tuple, Optional

# TFTP Opcodes
OPCODE_RRQ = 1      # Read Request
OPCODE_WRQ = 2      # Write Request
OPCODE_DATA = 3     # Data
OPCODE_ACK = 4      # Acknowledgment
OPCODE_ERROR = 5    # Error
OPCODE_DH_KEY = 6   # Diffie-Hellman Public Key Exchange

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
DEFAULT_BLOCK_SIZE = 512
SECURE_PLAINTEXT_BLOCK = 496      # Max plaintext size (512 - 16 bytes for GCM tag)
DEFAULT_TIMEOUT = 5
MAX_PACKET_SIZE = 4 + 512 + 16 + 10 # Opcode(2) + Block(2) + Max CT(528) + Buffer

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
DH_PRIME_P = int(DH_P_HEX, 16)
DH_GENERATOR_G = 2
DH_PUBLIC_KEY_SIZE= 256 # 2048 bits / 8 bytes

# Crypto (optional)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, hmac, serialization
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), default_backend())
    h.update(msg)
    return h.finalize()

def make_nonce(key: bytes, filename: str, direction: str, block_no: int) -> bytes:
    """
    12-byte GCM nonce derived from (session key, filename, direction, block_no).
    direction: 'dl' for server->client (RRQ), 'ul' for client->server (WRQ)
    """
    # Use the shared key, not PSK, for nonce derivation
    ctx = f"{direction}|{filename}|{block_no}".encode('utf-8')
    return hmac_sha256(key, ctx)[:12]

class SimpleTFTPServer:
    def __init__(self, host='localhost', port=69, root_dir='./files', mode='baseline', psk_hex=None):
        self.host = host
        self.port = port
        self.root_dir = root_dir
        self.mode = mode
        self.psk = bytes.fromhex(psk_hex) if (psk_hex and mode == 'secure') else None
        self.socket = None
        self.running = False
        
        # --- CRITICAL FIX: Use built-in DH parameters ---
        if HAVE_CRYPTO:
            numbers = dh.DHParameterNumbers(DH_PRIME_P, DH_GENERATOR_G)
            self.dh_params = numbers.parameters(default_backend())
        else:
            self.dh_params = None
        # ------------------------------------------------

        if self.mode in ('secure', 'secure_dh') and not HAVE_CRYPTO:
            raise SystemExit("cryptography is required for --mode secure/secure_dh. Try: pip install cryptography")
        
        # Key storage for DH mode, dynamically set per transfer
        self.shared_key = None

        # Create root directory if it doesn't exist
        os.makedirs(root_dir, exist_ok=True)

    def _generate_dh_keys_server(self) -> dh.DHPrivateKey:
        """Generate ephemeral DH private key for the server."""
        private_key = self.dh_params.generate_private_key()
        return private_key

    def _derive_shared_secret(self, private_key: dh.DHPrivateKey, client_public_key_bytes: bytes) -> bytes:
        """Derive the 256-bit shared key using HKDF."""
        try:
            # Deserialize the client's raw public number (Y)
            # Use the parameters from the private key itself to load the public key
            client_public_numbers = dh.DHPublicNumbers(
                int.from_bytes(client_public_key_bytes, 'big'),
                private_key.parameters().parameter_numbers() 
            )
            client_public_key = default_backend().load_dh_public_numbers(client_public_numbers)

            # Perform DH key agreement
            shared_secret = private_key.exchange(client_public_key)

            # Use C_PUB as the HKDF salt to ensure key diversity (client used the raw bytes for salt)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32, # 256 bits for AES-256
                salt=client_public_key_bytes, # Use client public key bytes as salt
                info=b'tftp-dh-key-derivation',
                backend=default_backend()
            ).derive(shared_secret)

            return derived_key
        except Exception as e:
            # Generic catch for key derivation failure
            print(f"Error deriving shared secret: {e}")
            return b''

    def start(self):
        """Start the TFTP server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True

            print(f"TFTP Server started on {self.host}:{self.port} (mode={self.mode})")
            print(f"Root directory: {self.root_dir}")
            print("Waiting for connections...")

            while self.running:
                try:
                    # Listen for initial RRQ/WRQ/DH_KEY on the main socket
                    data, client_addr = self.socket.recvfrom(MAX_PACKET_SIZE)
                    
                    if len(data) < 2:
                        continue
                    
                    opcode = struct.unpack('>H', data[:2])[0]

                    if opcode in (OPCODE_RRQ, OPCODE_WRQ):
                        print(f"Received initial request ({opcode}) from {client_addr}")
                        # Handle the complete request using a new transfer socket
                        self.handle_complete_request(data, client_addr)
                    else:
                        # Ignore other opcodes on the main port
                        pass 

                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the TFTP server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("TFTP Server stopped")

    def handle_complete_request(self, data: bytes, client_addr: Tuple[str, int]):
        """Handle a complete TFTP request from start to finish"""
        try:
            opcode = struct.unpack('>H', data[:2])[0]
            filename, mode = self.parse_request(data)
            filepath = os.path.join(self.root_dir, filename)

            # Create a new socket for this transfer (the TID)
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data_socket.bind(('', 0))  # Bind to any available port
            _, server_tid_port = data_socket.getsockname()
            data_socket.settimeout(DEFAULT_TIMEOUT)

            # Check DH setup if needed
            session_key = self.psk
            if self.mode == 'secure_dh':
                print(f"Transfer initiated with new TID: {server_tid_port}")
                session_key = self._setup_secure_transfer(filename, data_socket, client_addr)
                if not session_key:
                    self.send_error(client_addr, ERROR_NOT_DEFINED, "DH key exchange failed", data_socket)
                    data_socket.close()
                    return
            elif self.mode == 'secure':
                session_key = self.psk
            
            # --- Handle RRQ (Read) ---
            if opcode == OPCODE_RRQ:
                if not os.path.exists(filepath):
                    self.send_error(client_addr, ERROR_FILE_NOT_FOUND, "File not found", data_socket)
                    data_socket.close()
                    return
                elif not os.path.isfile(filepath):
                    self.send_error(client_addr, ERROR_ACCESS_VIOLATION, "Not a file", data_socket)
                    data_socket.close()
                    return
                else:
                    print(f"Read request: {filename} from {client_addr} on TID {server_tid_port}")
                    self.send_file(filepath, filename, client_addr, data_socket, session_key)

            # --- Handle WRQ (Write) ---
            elif opcode == OPCODE_WRQ:
                if os.path.exists(filepath):
                    self.send_error(client_addr, ERROR_FILE_EXISTS, "File already exists", data_socket)
                    data_socket.close()
                    return
                else:
                    print(f"Write request: {filename} from {client_addr} on TID {server_tid_port}")
                    self.receive_file(filepath, filename, client_addr, data_socket, session_key)
            
            # Close the transfer socket
            data_socket.close()

        except Exception as e:
            print(f"Error handling request from {client_addr}: {e}")
            if 'data_socket' in locals():
                self.send_error(client_addr, ERROR_NOT_DEFINED, "Server error", data_socket)
            else:
                self.send_error(client_addr, ERROR_NOT_DEFINED, "Server error")

    def _setup_secure_transfer(self, filename: str, data_socket: socket.socket, client_addr: Tuple[str, int]) -> Optional[bytes]:
        """Performs the Diffie-Hellman key exchange."""
        # Custom parameters for DH setup robustness
        DH_RETRANSMIT_COUNT = 15 
        DH_TIMEOUT = 15 
        
        try:
            # 1. Generate Server's ephemeral key pair
            server_private_key = self._generate_dh_keys_server()
            server_public_key = server_private_key.public_key()
            
            # Serialize the public number (Y) as a fixed-size byte string
            server_public_key_bytes = server_public_key.public_numbers().y.to_bytes(DH_PUBLIC_KEY_SIZE, 'big')

            # 2. Send Server's Public Key (S_PUB) in DH_KEY packet
            s_pub_packet = struct.pack('>H', OPCODE_DH_KEY) + server_public_key_bytes
            print(f"Sent S_PUB. Waiting for C_PUB from {client_addr}...")

            client_public_key_bytes = None

            # Retry sending S_PUB and waiting for C_PUB 
            for _ in range(DH_RETRANSMIT_COUNT):
                data_socket.sendto(s_pub_packet, client_addr)
                try:
                    data_socket.settimeout(DH_TIMEOUT) # Use extended timeout for handshake
                    data, addr = data_socket.recvfrom(MAX_PACKET_SIZE)

                    if addr != client_addr or len(data) < 2:
                        continue
                    
                    opcode = struct.unpack('>H', data[:2])[0]
                    
                    if opcode == OPCODE_DH_KEY:
                        client_public_key_bytes = data[2:]
                        # CRITICAL FIX: Check for the exact raw key size
                        if len(client_public_key_bytes) == DH_PUBLIC_KEY_SIZE:
                            break
                        else:
                            print(f"Warning: Received DH_KEY packet with incorrect size ({len(client_public_key_bytes)} bytes).")
                    elif opcode == OPCODE_ERROR:
                        print("Received ERROR during DH setup.")
                        return None
                    
                except socket.timeout:
                    # Retrying S_PUB ensures the client gets the server's TID
                    continue
            
            if not client_public_key_bytes or len(client_public_key_bytes) != DH_PUBLIC_KEY_SIZE:
                print("Failed to receive C_PUB after multiple retries or key size mismatch.")
                return None

            # 3. Derive shared key
            shared_key = self._derive_shared_secret(server_private_key, client_public_key_bytes)
            if shared_key:
                print("DH exchange successful. Shared key derived.")
                return shared_key
            else:
                return None
            
        except Exception as e:
            print(f"DH Key Exchange failed: {e}")
            return None

    def parse_request(self, data: bytes) -> Tuple[str, str]:
        """Parse RRQ/WRQ packet to extract filename and mode"""
        remaining = data[2:]
        null_pos = remaining.find(b'\x00')
        if null_pos == -1:
            raise ValueError("Invalid request format (filename missing terminator)")

        filename = remaining[:null_pos].decode('ascii')
        remaining = remaining[null_pos + 1:]

        null_pos = remaining.find(b'\x00')
        if null_pos == -1:
            raise ValueError("Invalid request format (mode missing terminator)")

        mode = remaining[:null_pos].decode('ascii').lower()
        if mode not in ['netascii', 'octet']:
            raise ValueError("Unsupported mode")

        return filename, mode

    def send_file(self, filepath: str, filename: str, client_addr: Tuple[str, int], data_socket: socket.socket, session_key: Optional[bytes]):
        """Send file to client"""
        is_secure = self.mode in ('secure', 'secure_dh')
        block_size = SECURE_PLAINTEXT_BLOCK if is_secure else DEFAULT_BLOCK_SIZE
        
        try:
            with open(filepath, 'rb') as f:
                block_num = 1
                while True:
                    pt = f.read(block_size)
                    if pt is None: pt = b''

                    if is_secure:
                        aes = AESGCM(session_key)
                        nonce = make_nonce(session_key, filename, 'dl', block_num)
                        aad = f"{filename}|{block_num}|dl".encode('utf-8')
                        payload = aes.encrypt(nonce, pt, aad)
                    else:
                        payload = pt

                    packet = struct.pack('>HH', OPCODE_DATA, block_num) + payload

                    # Retry sending data until we get the matching ACK
                    for _ in range(8): # 8 retransmission attempts
                        data_socket.sendto(packet, client_addr)

                        try:
                            data_socket.settimeout(DEFAULT_TIMEOUT)
                            ack_data, ack_addr = data_socket.recvfrom(MAX_PACKET_SIZE)
                        except socket.timeout:
                            continue # Retry sending DATA
                        except Exception:
                            break 

                        if ack_addr != client_addr or len(ack_data) < 4:
                            continue

                        ack_opcode, ack_block = struct.unpack('>HH', ack_data[:4])

                        if ack_opcode == OPCODE_ERROR:
                            error_code = struct.unpack('>H', ack_data[2:4])[0]
                            error_msg = ack_data[4:-1].decode('ascii')
                            print(f"Client error {error_code}: {error_msg}")
                            return
                        
                        if ack_opcode == OPCODE_ACK and ack_block == block_num:
                            break 
                    else:
                        print(f"Server: Giving up on block {block_num} after retries.")
                        return

                    if len(pt) < block_size:
                        break # Last block sent

                    block_num += 1

                print(f"File sent successfully to {client_addr}")

        except Exception as e:
            print(f"Error sending file: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "File send error", data_socket)

    def receive_file(self, filepath: str, filename: str, client_addr: Tuple[str, int], data_socket: socket.socket, session_key: Optional[bytes]):
        """Receive file from client"""
        is_secure = self.mode in ('secure', 'secure_dh')
        
        try:
            # Send initial ACK(0)
            ack_packet = struct.pack('>HH', OPCODE_ACK, 0)
            data_socket.sendto(ack_packet, client_addr)

            with open(filepath, 'wb') as f:
                expected_block = 1

                while True:
                    data_socket.settimeout(DEFAULT_TIMEOUT)
                    
                    for _ in range(8):
                        try:
                            data, addr = data_socket.recvfrom(MAX_PACKET_SIZE)
                        except socket.timeout:
                            print(f"Timeout waiting for DATA({expected_block}). Retrying ACK({expected_block - 1})")
                            ack_packet = struct.pack('>HH', OPCODE_ACK, expected_block - 1)
                            data_socket.sendto(ack_packet, client_addr)
                            continue
                        
                        if addr != client_addr or len(data) < 4: continue

                        opcode, block_num = struct.unpack('>HH', data[:4])

                        if opcode == OPCODE_ERROR:
                            print("Received ERROR from client.")
                            return

                        if opcode != OPCODE_DATA: continue
                        
                        if block_num < expected_block:
                            ack_packet = struct.pack('>HH', OPCODE_ACK, block_num)
                            data_socket.sendto(ack_packet, client_addr)
                            continue

                        if block_num == expected_block:
                            break
                    else:
                        print(f"Timeout waiting for DATA({expected_block}) after retries.")
                        return

                    payload = data[4:]
                    
                    if is_secure:
                        try:
                            aes = AESGCM(session_key)
                            nonce = make_nonce(session_key, filename, 'ul', block_num)
                            aad = f"{filename}|{block_num}|ul".encode('utf-8')
                            pt = aes.decrypt(nonce, payload, aad)
                        except Exception as e:
                            print(f"Decrypt failed on block {block_num}: {e}")
                            ack_packet = struct.pack('>HH', OPCODE_ACK, expected_block - 1)
                            data_socket.sendto(ack_packet, client_addr)
                            continue
                        f.write(pt)
                        ack_packet = struct.pack('>HH', OPCODE_ACK, block_num)
                        data_socket.sendto(ack_packet, client_addr)
                        if len(pt) < SECURE_PLAINTEXT_BLOCK: break
                    else:
                        file_data = payload
                        f.write(file_data)
                        ack_packet = struct.pack('>HH', OPCODE_ACK, block_num)
                        data_socket.sendto(ack_packet, client_addr)
                        if len(file_data) < DEFAULT_BLOCK_SIZE: break

                    expected_block += 1

            print(f"File received successfully from {client_addr}")

        except Exception as e:
            print(f"Error receiving file: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "File receive error", data_socket)


    def send_error(self, client_addr: Tuple[str, int], error_code: int, error_msg: str, sock: Optional[socket.socket] = None):
        """Send error packet to client using the appropriate socket."""
        try:
            error_packet = struct.pack('>HH', OPCODE_ERROR, error_code)
            error_packet += error_msg.encode('ascii') + b'\x00'
            
            target_sock = sock if sock else self.socket
            
            if target_sock:
                target_sock.sendto(error_packet, client_addr)
        except Exception as e:
            print(f"Error sending error packet: {e}")


def main():
    """Main function to run TFTP server"""
    parser = argparse.ArgumentParser(description='Simple TFTP Server (+ secure mode)')
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=6969, help='Server port')
    parser.add_argument('--root-dir', default='./files', help='Root directory for files')
    parser.add_argument('--mode', choices=['baseline','secure', 'secure_dh'], default='baseline', help='Transfer mode (secure_dh uses DH key exchange)')
    parser.add_argument('--psk', default=None, help='Hex-encoded 32-byte key (AES-256-GCM) for secure mode')

    args = parser.parse_args()
    if args.mode == 'secure' and not args.psk:
        print("Error: --psk is required for --mode secure")
        sys.exit(1)

    # Use port 6969 in the demo environment for consistency
    port = args.port if args.port != 69 else 6969
    server = SimpleTFTPServer(args.host, port, args.root_dir, args.mode, args.psk)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()

if __name__ == '__main__':
    main()

