#!/usr/bin/env python3
"""
TFTP Client Implementation with DH Key Exchange and AES-GCM Encryption.
Supports 'baseline', 'secure' (PSK), and 'secure_dh' (Diffie-Hellman).
"""

import socket
import struct
import os
import sys
import argparse
import time
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
SECURE_PLAINTEXT_BLOCK = 496  # secure mode plaintext per DATA block (ct+tag ~= 512)
DEFAULT_TIMEOUT = 5
MAX_PACKET_SIZE = 532         # Needs to accommodate encrypted data (516) or DH key (258)

# Crypto (mandatory for secure modes)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
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
        self.shared_key = None # Used for secure_dh mode
        if self.mode in ['secure', 'secure_dh'] and not HAVE_CRYPTO:
            raise SystemExit("cryptography is required for secure modes. Try: pip install cryptography")
        self.socket = None
        
        # DH Initialization
        self.dh_parameters = None
        if self.mode == 'secure_dh':
            # Use manual DH ParameterNumbers definition for compatibility
            try:
                numbers = dh.DHParameterNumbers(DH_P, DH_G)
                self.dh_parameters = numbers.parameters(default_backend())
            except Exception as e:
                # Catch failures in parameter creation itself
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
        private_key = self.dh_parameters.generate_private_key()
        pub_key = private_key.public_key()
        
        # Serialize the public number (Y) as a fixed-size byte string
        public_key_bytes = pub_key.public_numbers().y.to_bytes(DH_KEY_SIZE, 'big')
        return private_key, public_key_bytes

    def _derive_shared_secret(self, client_private_key: dh.DHPrivateKey, peer_public_key_bytes: bytes, salt: bytes) -> bytes:
        """Derives the 32-byte AES key using HKDF from the DH shared secret."""
        try:
            # Deserialize the peer's raw public number (Y)
            peer_public_numbers = dh.DHPublicNumbers(
                int.from_bytes(peer_public_key_bytes, 'big'),
                client_private_key.parameters().parameter_numbers() # Use params from client's private key
            )
            peer_public_key = default_backend().load_dh_public_numbers(peer_public_numbers)
            
            # Perform DH key agreement
            shared_secret = client_private_key.exchange(peer_public_key)

            # HKDF to derive a strong 32-byte AES key
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b'tftp-dh-key-derivation', # Updated to match server
                backend=default_backend()
            ).derive(shared_secret)
            
            return key
        except Exception as e:
            # Re-raise with a specific message to help debug DH failures
            raise RuntimeError(f"Error computing shared key: {e}")

    def _parse_error(self, data: bytes) -> Tuple[int, str]:
        """Parse error packet"""
        try:
            error_code = struct.unpack('>H', data[2:4])[0]
            error_msg = data[4:-1].decode('ascii')
            return error_code, error_msg
        except:
            return ERROR_NOT_DEFINED, "Unknown error"

    def _perform_dh_key_exchange(self, sock: socket.socket, initial_packet: bytes, client_addr: Tuple[str, int], retries=8) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """
        Handles the client-side of the DH handshake, starting from the server's S_PUB.
        Returns the derived shared key and the confirmed transfer address (TID).
        """
        print("Starting DH key exchange...")
        
        # 1. Generate Client DH Key Pair
        client_private_key, client_public_key_bytes = self._generate_dh_keys_client()
        
        # 2. Process initial_packet (S_PUB)
        op, = struct.unpack('>H', initial_packet[:2])
        
        # CRITICAL FIX: Check expected length (2 bytes opcode + 256 bytes raw key)
        if op != OPCODE_DH_KEY or len(initial_packet) != 2 + DH_KEY_SIZE:
             print("Received unexpected packet instead of S_PUB.")
             return None

        server_public_key_bytes = initial_packet[2:]
        
        # 3. Derive Shared Key using C_PUB as salt/context (MUST MATCH SERVER)
        shared_key = self._derive_shared_secret(
            client_private_key, 
            server_public_key_bytes, 
            client_public_key_bytes # Use C_PUB as salt to match server implementation
        )

        # 4. Send Client Public Key (C_PUB) back to the new server TID
        c_pub_packet = struct.pack('>H', OPCODE_DH_KEY) + client_public_key_bytes
        transfer_addr = client_addr
        
        # Send C_PUB with retry to ensure server gets it
        for i in range(3): # Send C_PUB a few times for reliability
            sock.sendto(c_pub_packet, transfer_addr)
            time.sleep(0.1) 
            
        print("DH exchange successful. Shared key derived.")
        return shared_key, transfer_addr

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

            # 2. Perform DH exchange if necessary
            if self.mode == 'secure_dh':
                result = self._perform_dh_key_exchange(sock, initial_data, initial_addr)
                if not result:
                    return False
                self.shared_key, transfer_addr = result
                # After successful DH, we expect DATA(1) next.
                initial_data = b'' 
            else:
                transfer_addr = initial_addr
                initial_data = initial_data # Initial data is ACK(0) or DATA(1)
            
            current_packet = initial_data # Start processing from the first received packet
            expected_block = 1

            with open(local_filename, 'wb') as f:
                while True:
                    data, addr = b'', None
                    
                    if current_packet:
                        data = current_packet
                        current_packet = b'' # Process the handshake packet first
                    else:
                        try:
                            data, addr = sock.recvfrom(MAX_PACKET_SIZE)
                        except socket.timeout:
                            # Retransmit the last ACK to prompt retransmit
                            if expected_block > 1:
                                sock.sendto(struct.pack('>HH', OPCODE_ACK, expected_block - 1), transfer_addr)
                                print(f"Timeout: Resending ACK {expected_block - 1}")
                                continue
                            else:
                                # For initial block (1), just time out, since we sent C_PUB in DH phase.
                                print("Transfer failed: Timeout waiting for DATA(1).")
                                return False
                    
                    if not data or len(data) < 4: continue
                    if addr != transfer_addr and addr is not None: 
                        sock.sendto(struct.pack('>HH', OPCODE_ERROR, ERROR_UNKNOWN_TID), addr)
                        continue

                    opcode, block_num = struct.unpack('>HH', data[:4])

                    if opcode == OPCODE_ERROR:
                        error_code, error_msg = self._parse_error(data)
                        print(f"Server error {error_code}: {error_msg}")
                        return False

                    if opcode != OPCODE_DATA: continue
                    if block_num != expected_block:
                        # Ignore out-of-order/duplicate blocks; re-ACK last good
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, max(0, expected_block - 1)), transfer_addr)
                        continue

                    payload = data[4:]
                    transfer_key = self.shared_key if self.mode == 'secure_dh' else self.psk
                    
                    if self.mode in ['secure', 'secure_dh']:
                        aes = AESGCM(transfer_key)
                        nonce = make_nonce(transfer_key, remote_filename, 'dl', block_num)
                        aad = f"{remote_filename}|{block_num}|dl".encode('utf-8')
                        try:
                            file_data = aes.decrypt(nonce, payload, aad)
                        except Exception as e:
                            print(f"Decryption failed on block {block_num}: {e}")
                            sock.sendto(struct.pack('>HH', OPCODE_ACK, expected_block - 1), transfer_addr)
                            continue
                        
                        f.write(file_data)
                        sock.sendto(struct.pack('>HH', OPCODE_ACK, block_num), transfer_addr)
                        if len(file_data) < SECURE_PLAINTEXT_BLOCK: break
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

    def put_file(self, local_filename: str, remote_filename: str = None) -> bool:
        """Upload a file to the TFTP server"""
        if remote_filename is None: remote_filename = local_filename
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
            # 1. Send initial WRQ (retry loop for handshake initiation)
            initial_data, initial_addr = b'', None
            for _ in range(20):
                sock.sendto(wrq_packet, server_initial_addr)
                try:
                    initial_data, initial_addr = sock.recvfrom(MAX_PACKET_SIZE)
                    if initial_addr[1] != self.server_port: # Received response from a new TID
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
                    if pt is None: pt = b''

                    if self.mode in ['secure', 'secure_dh']:
                        aes = AESGCM(transfer_key)
                        nonce = make_nonce(transfer_key, remote_filename, 'ul', block_num)
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
                            
                        if ack_addr != transfer_addr or len(ack_data) < 4: continue
                        
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


def main():
    """Main function for TFTP client"""
    parser = argparse.ArgumentParser(description='Secure TFTP Client (PSK + DH)')
    parser.add_argument('--server', default='localhost', help='TFTP server host')
    parser.add_argument('--port', type=int, default=69, help='TFTP server port')
    parser.add_argument('--mode', choices=['baseline','secure','secure_dh'], default='baseline', help='Transfer mode')
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

