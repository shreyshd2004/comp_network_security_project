#!/usr/bin/env python3
"""
Simplified TFTP Server Implementation (+ optional AES-GCM with PSK/DH)
Handles one request at a time; in secure mode, encrypts/decrypts DATA using a pre-shared key or DH-derived session key.
"""

import socket
import struct
import os
import sys
import argparse
import time
from typing import Tuple

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

# --- Diffie-Hellman Constants ---
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
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
        self.session_keys = {}
        self.socket = None
        self.running = False
        
        if self.mode in ['secure', 'secure_dh'] and not HAVE_CRYPTO:
            raise SystemExit("cryptography is required for secure modes. Try: pip install cryptography")

        if self.mode == 'secure_dh' and HAVE_CRYPTO:
            try:
                # Use standard parameters object
                self.dh_params = dh.DHParameterNumbers(DH_PRIME_P, DH_GENERATOR_G).parameters(backend=None)
            except Exception as e:
                # Fallback check
                try:
                    self.dh_params = dh.generate_parameters(generator=DH_GENERATOR_G, key_size=2048, backend=None)
                except Exception:
                    raise SystemExit(f"Failed to create DH parameters: {e}")
        else:
            self.dh_params = None
            
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

                except KeyboardInterrupt:
                    raise
                
                except Exception as e:
                    print(f"Unexpected error in main loop: {e}")


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

    def _close_socket(self, sock, client_addr_string=None):
        sock.close()
        if self.mode == 'secure_dh' and HAVE_CRYPTO and not self.session_keys.get(client_addr_string, None):
            del self.session_keys[client_addr_string]


    def _generate_dh_keys_server(self) -> Tuple[dh.DHPrivateKey, bytes]:
        """Generate ephemeral DH private key for the server."""
        private_key = self.dh_params.generate_private_key()
        pub_key = private_key.public_key()

        # Serialize the public number (Y) as a fixed-size byte string
        public_key_bytes = pub_key.public_numbers().y.to_bytes(DH_PUBLIC_KEY_SIZE, 'big')

        return private_key, public_key_bytes

    def _derive_shared_secret(self, private_key: dh.DHPrivateKey, client_public_key_bytes: bytes) -> bytes:
        """Derive the 256-bit shared key using HKDF."""
        try:
            # Deserialize the client's raw public number (Y)
            client_public_numbers = dh.DHPublicNumbers(
                int.from_bytes(client_public_key_bytes, 'big'),
                private_key.parameters().parameter_numbers() 
            )
            client_public_key = client_public_numbers.public_key()

            # Perform DH key agreement
            shared_secret = private_key.exchange(client_public_key)

            # Use C_PUB as the HKDF salt to ensure key diversity (client used the raw bytes for salt)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32, # 256 bits for AES-256
                salt=client_public_key_bytes, # Use client public key bytes as salt
                info=b'tftp-dh-key-derivation'
            ).derive(shared_secret)

            return derived_key
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            return b''


    def _handle_dh_key_exchange(self, sock: socket.socket, client_addr: Tuple[str, int]):
        """
        Performs the Diffie-Hellman key exchange. 
        Client sends RRQ/WRQ, Server sends S_PUB, Client sends C_PUB, Server derives key.
        """
        DH_RETRANSMIT_COUNT = 3
        DH_TIMEOUT = 1.0 # Use smaller timeout inside the loop

        try:
            # 1. Generate Server's ephemeral key pair
            server_private_key, server_public_key_bytes = self._generate_dh_keys_server()

            # 2. Send Server's Public Key (S_PUB) in DH_KEY packet
            s_pub_packet = struct.pack('>H', OPCODE_DH_KEY) + server_public_key_bytes
            
            client_public_key_bytes = None
            sock.settimeout(DH_TIMEOUT)

            # Retry sending S_PUB and waiting for C_PUB
            for _ in range(DH_RETRANSMIT_COUNT):
                sock.sendto(s_pub_packet, client_addr)

                try:
                    data, addr = sock.recvfrom(MAX_PACKET_SIZE)

                    if addr != client_addr or len(data) < 2:
                        continue
                    
                    opcode = struct.unpack('>H', data[:2])[0]
                    
                    if opcode == OPCODE_DH_KEY:
                        client_public_key_bytes = data[2:]
                        # CRITICAL: Check for the exact raw key size
                        if len(client_public_key_bytes) == DH_PUBLIC_KEY_SIZE:
                            break
                        else:
                            print(f"Warning: Received DH_KEY packet with incorrect size ({len(client_public_key_bytes)} bytes).")
                    elif opcode == OPCODE_ERROR:
                        print("Received ERROR during DH setup.")
                        return
                        
                except socket.timeout:
                    continue # Retry S_PUB send
            
            # Reset timeout to default after handshake
            sock.settimeout(DEFAULT_TIMEOUT)
            
            if not client_public_key_bytes or len(client_public_key_bytes) != DH_PUBLIC_KEY_SIZE:
                print("Failed to receive C_PUB after multiple retries or key size mismatch.")
                return

            # 3. Derive shared key
            shared_key = self._derive_shared_secret(server_private_key, client_public_key_bytes)
            if shared_key:
                print("DH exchange successful. Shared key derived.")
                client_addr_string = client_addr[0] + str(client_addr[1])
                self.session_keys[client_addr_string] = shared_key
                print(f"Stored session key for TID {client_addr_string}")

            return
            
        except Exception as e:
            print(f"DH Key Exchange failed: {e}")
            return


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
        MAX_RETRIES = 3
        try:
            # Create a new socket for this transfer
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data_socket.bind(('', 0))  # Bind to any available port
            data_socket.settimeout(DEFAULT_TIMEOUT)

            # FIX 2: Check for DH mode explicitly
            if self.mode == 'secure_dh' and HAVE_CRYPTO:
                print("Attempting DH Key exchange")
                self._handle_dh_key_exchange(data_socket, client_addr)
            

            with open(filepath, 'rb') as f:
                block_num = 1
                while True:
                    pt = f.read(SECURE_PLAINTEXT_BLOCK if self.mode in ['secure', 'secure_dh'] else DEFAULT_BLOCK_SIZE)
                    if pt is None:
                        pt = b''

                    # FIX 4: Check for both secure modes
                    if self.mode in ['secure', 'secure_dh']:
                        client_addr_string = client_addr[0] + str(client_addr[1])
                        
                        # Use session key if available (DH) or fallback to PSK (PSK mode)
                        session_keys = self.session_keys.get(client_addr_string) or self.psk
                        
                        if session_keys is None:
                            raise Exception("Secure mode requested but no session key or PSK available.")

                        aes = AESGCM(session_keys)
                        
                        # FIX 1: Change NONCE direction from 'ul' to 'dl' for file download (RRQ)
                        nonce = make_nonce(session_keys, filename, 'dl', block_num)
                        
                        aad = f"{filename}|{block_num}|dl".encode('utf-8')
                        payload = aes.encrypt(nonce, pt, aad)
                    else:
                        payload = pt

                    packet = struct.pack('>HH', OPCODE_DATA, block_num) + payload


                    # Wait for ACK (retries kept simple)
                    retries = 0
                    while retries < MAX_RETRIES:
                        try:
                            # Send packet from data socket
                            data_socket.sendto(packet, client_addr)
                            if self.wait_for_ack_from_socket(data_socket, block_num, client_addr):
                                break
                            else:
                                print(f"Timeout waiting for ACK {block_num}. Retrying...")
                                print(f"Local Socket address: {data_socket.getsockname()}")
                                print(f"Client Addr: {client_addr}")
                            retries += 1
                            time.sleep(0.1)
                        except socket.timeout:
                            print(f"Timeout waiting for ACK {block_num}")
                            self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
                            return
                        except Exception as e:
                                print(f"Unexpected error during ACK wait for block {block_num}: {e}")
                                self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
                                return

                    if retries == MAX_RETRIES:
                        print(f"Retry Limit Reached: Timeout waiting for ACK {block_num}")
                        self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
                        return

                    if len(pt) < (SECURE_PLAINTEXT_BLOCK if self.mode in ['secure', 'secure_dh'] else DEFAULT_BLOCK_SIZE):
                        break

                    block_num += 1

                # Send empty DATA packet to signal end (baseline convention)
                packet = struct.pack('>HH', OPCODE_DATA, block_num + 1) + b''
                data_socket.sendto(packet, client_addr)
                # best-effort final ACK
                try:
                    self.wait_for_ack_from_socket(data_socket, block_num + 1, client_addr)
                except Exception:
                    pass

            self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
            print(f"File sent successfully to {client_addr}")

        except Exception as e:
            print(f"Error sending file: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "File send error", data_socket)

    def receive_file(self, filepath: str, filename: str, client_addr: Tuple[str, int], data_socket: socket.socket, session_key: Optional[bytes]):
        """Receive file from client"""
        is_secure = self.mode in ('secure', 'secure_dh')
        
        try:
            # Create a new socket for this transfer
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data_socket.bind(('', 0))  # Bind to any available port

            # FIX 3: Check for DH mode explicitly and pass socket
            if self.mode == 'secure_dh' and HAVE_CRYPTO:
                print("Attempting DH Key exchange")
                self._handle_dh_key_exchange(data_socket, client_addr)

            # Send initial ACK (ACK 0)
            ack_packet = struct.pack('>HH', OPCODE_ACK, 0)
            data_socket.sendto(ack_packet, client_addr)

            with open(filepath, 'wb') as f:
                expected_block = 1

                while True:
                    data_socket.settimeout(DEFAULT_TIMEOUT)
                    try:
                        data, addr = data_socket.recvfrom(MAX_PACKET_SIZE)
                        
                        # Handle potential DH Key response from client (C_PUB) if running DH mode
                        if len(data) >= 2:
                            opcode = struct.unpack('>H', data[:2])[0]
                            if opcode == OPCODE_DH_KEY:
                                # Ignore DH response if we already have the key, or if it's the wrong mode.
                                # The DH response is handled asynchronously by the server side DH loop during exchange.
                                continue

                        if addr != client_addr:
                            print(f"Received packet from unexpected address: {addr}")
                            # Send ERROR_UNKNOWN_TID (error code 5)
                            error_packet = struct.pack('>HH', OPCODE_ERROR, ERROR_UNKNOWN_TID) + b'Unknown TID\x00'
                            data_socket.sendto(error_packet, addr)
                            continue
                            
                        if len(data) < 4:
                            print("Invalid packet received")
                            continue
                            
                    except socket.timeout:
                        print("Timeout waiting for data")
                        self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
                        return

                    opcode, block_num = struct.unpack('>HH', data[:4])

                    if opcode != OPCODE_DATA:
                        print(f"Expected DATA packet, got opcode {opcode}")
                        self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
                        return

                        if block_num == expected_block:
                            break
                    else:
                        print(f"Timeout waiting for DATA({expected_block}) after retries.")
                        return

                    payload = data[4:]
                    # FIX 4: Check for both secure modes
                    if self.mode in ['secure', 'secure_dh']:
                        try:
                            client_addr_string = client_addr[0] + str(client_addr[1])
                            
                            # Use session key if available (DH) or fallback to PSK (PSK mode)
                            session_keys = self.session_keys.get(client_addr_string) or self.psk
                            if session_keys is None:
                                raise Exception("Secure mode requested but no session key or PSK available.")
                            
                            aes = AESGCM(session_keys)
                            # Nonce and AAD for WRQ/Upload are both 'ul'
                            nonce = make_nonce(session_keys, filename, 'ul', block_num)
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

            self._close_socket(data_socket, client_addr[0]+str(client_addr[1]))
            print(f"File received successfully from {client_addr}")

        except Exception as e:
            print(f"Error receiving file: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "File receive error")

    def wait_for_ack_from_socket(self, sock: socket.socket, block_num: int, client_addr: Tuple[str, int]) -> bool:
        """Wait for ACK packet from specific socket with timeout"""
        sock.settimeout(DEFAULT_TIMEOUT)
        try:
            data, addr = sock.recvfrom(MAX_PACKET_SIZE)
            
            # Allow packets from the original server port if we are still setting up TID
            if addr != client_addr:
                # Handle stray packets, but only process ACKs from the expected client address
                return False


            opcode, ack_block = struct.unpack('>HH', data[:4])
            return opcode == OPCODE_ACK and ack_block == block_num

        except socket.timeout:
            return False
        # Do not use finally: sock.settimeout(None) here, as timeout needs to be reset outside
        # the function or managed by the caller's loop.

    def send_error(self, client_addr: Tuple[str, int], error_code: int, error_msg: str):
        """Send error packet to client"""
        try:
            error_packet = struct.pack('>HH', OPCODE_ERROR, error_code)
            error_packet += error_msg.encode('ascii') + b'\x00'
            # Use the main server socket for errors, as the transfer socket might be closed
            self.socket.sendto(error_packet, client_addr) 
        except Exception as e:
            print(f"Error sending error packet: {e}")


def main():
    """Main function to run TFTP server"""
    parser = argparse.ArgumentParser(description='Simple TFTP Server (+ secure mode)')
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=6969, help='Server port')
    parser.add_argument('--root-dir', default='./files', help='Root directory for files')
    parser.add_argument('--mode', choices=['baseline','secure', 'secure_dh'], default='baseline', help='Transfer mode')
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

