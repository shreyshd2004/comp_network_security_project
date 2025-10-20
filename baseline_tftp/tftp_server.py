#!/usr/bin/env python3
"""
Simplified TFTP Server Implementation
A more robust baseline implementation that handles one request at a time
"""

import socket
import struct
import os
import sys
import argparse
from typing import Tuple, Optional

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
DEFAULT_BLOCK_SIZE = 512
DEFAULT_TIMEOUT = 5
MAX_DATA_SIZE = 512
MAX_PACKET_SIZE = 516  # 4 bytes header + 512 bytes data

class SimpleTFTPServer:
    def __init__(self, host='localhost', port=69, root_dir='./files'):
        self.host = host
        self.port = port
        self.root_dir = root_dir
        self.socket = None
        self.running = False
        
        # Create root directory if it doesn't exist
        os.makedirs(root_dir, exist_ok=True)
        
    def start(self):
        """Start the TFTP server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            print(f"TFTP Server started on {self.host}:{self.port}")
            print(f"Root directory: {self.root_dir}")
            print("Waiting for connections...")
            
            while self.running:
                try:
                    data, client_addr = self.socket.recvfrom(MAX_PACKET_SIZE)
                    print(f"Received request from {client_addr}")
                    
                    # Handle the complete request
                    self.handle_complete_request(data, client_addr)
                    
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
            if len(data) < 2:
                self.send_error(client_addr, ERROR_NOT_DEFINED, "Invalid packet")
                return
                
            opcode = struct.unpack('>H', data[:2])[0]
            
            if opcode == OPCODE_RRQ:
                self.handle_read_request(data, client_addr)
            elif opcode == OPCODE_WRQ:
                self.handle_write_request(data, client_addr)
            else:
                self.send_error(client_addr, ERROR_ILLEGAL_OPERATION, "Invalid opcode")
                
        except Exception as e:
            print(f"Error handling request from {client_addr}: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "Server error")
            
    def handle_read_request(self, data: bytes, client_addr: Tuple[str, int]):
        """Handle read request (RRQ)"""
        try:
            # Parse filename and mode
            filename, mode = self.parse_request(data)
            filepath = os.path.join(self.root_dir, filename)
            
            # Check if file exists
            if not os.path.exists(filepath):
                self.send_error(client_addr, ERROR_FILE_NOT_FOUND, "File not found")
                return
                
            # Check if it's a file (not directory)
            if not os.path.isfile(filepath):
                self.send_error(client_addr, ERROR_ACCESS_VIOLATION, "Not a file")
                return
                
            print(f"Read request: {filename} from {client_addr}")
            self.send_file(filepath, client_addr)
            
        except Exception as e:
            print(f"Error in read request: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "Read request error")
            
    def handle_write_request(self, data: bytes, client_addr: Tuple[str, int]):
        """Handle write request (WRQ)"""
        try:
            # Parse filename and mode
            filename, mode = self.parse_request(data)
            filepath = os.path.join(self.root_dir, filename)
            
            # Check if file already exists
            if os.path.exists(filepath):
                self.send_error(client_addr, ERROR_FILE_EXISTS, "File already exists")
                return
                
            print(f"Write request: {filename} from {client_addr}")
            self.receive_file(filepath, client_addr)
            
        except Exception as e:
            print(f"Error in write request: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "Write request error")
            
    def parse_request(self, data: bytes) -> Tuple[str, str]:
        """Parse RRQ/WRQ packet to extract filename and mode"""
        try:
            # Skip opcode (2 bytes)
            remaining = data[2:]
            
            # Find null terminator for filename
            null_pos = remaining.find(b'\x00')
            if null_pos == -1:
                raise ValueError("Invalid request format")
                
            filename = remaining[:null_pos].decode('ascii')
            remaining = remaining[null_pos + 1:]
            
            # Find null terminator for mode
            null_pos = remaining.find(b'\x00')
            if null_pos == -1:
                raise ValueError("Invalid request format")
                
            mode = remaining[:null_pos].decode('ascii').lower()
            
            if mode not in ['netascii', 'octet']:
                raise ValueError("Unsupported mode")
                
            return filename, mode
            
        except Exception as e:
            raise ValueError(f"Failed to parse request: {e}")
            
    def send_file(self, filepath: str, client_addr: Tuple[str, int]):
        """Send file to client"""
        try:
            # Create a new socket for this transfer
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data_socket.bind(('', 0))  # Bind to any available port
            
            with open(filepath, 'rb') as f:
                block_num = 1
                
                while True:
                    data = f.read(DEFAULT_BLOCK_SIZE)
                    if not data:
                        break
                        
                    # Create DATA packet
                    packet = struct.pack('>HH', OPCODE_DATA, block_num) + data
                    
                    # Send packet from data socket
                    data_socket.sendto(packet, client_addr)
                    
                    # Wait for ACK
                    if not self.wait_for_ack_from_socket(data_socket, block_num, client_addr):
                        print(f"Timeout waiting for ACK {block_num}")
                        data_socket.close()
                        return
                        
                    block_num += 1
                    
                # Send empty DATA packet to signal end
                packet = struct.pack('>HH', OPCODE_DATA, block_num) + b''
                data_socket.sendto(packet, client_addr)
                self.wait_for_ack_from_socket(data_socket, block_num, client_addr)
                
            data_socket.close()
            print(f"File sent successfully to {client_addr}")
            
        except Exception as e:
            print(f"Error sending file: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "File send error")
            
    def receive_file(self, filepath: str, client_addr: Tuple[str, int]):
        """Receive file from client"""
        try:
            # Create a new socket for this transfer
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data_socket.bind(('', 0))  # Bind to any available port
            
            # Send initial ACK
            ack_packet = struct.pack('>HH', OPCODE_ACK, 0)
            data_socket.sendto(ack_packet, client_addr)
            
            with open(filepath, 'wb') as f:
                expected_block = 1
                
                while True:
                    # Receive DATA packet
                    data_socket.settimeout(DEFAULT_TIMEOUT)
                    try:
                        data, addr = data_socket.recvfrom(MAX_PACKET_SIZE)
                        if addr != client_addr:
                            print(f"Received packet from unexpected address: {addr}")
                            data_socket.close()
                            return
                    except socket.timeout:
                        print("Timeout waiting for data")
                        data_socket.close()
                        return
                    finally:
                        data_socket.settimeout(None)
                        
                    if len(data) < 4:
                        print("Invalid packet received")
                        data_socket.close()
                        return
                        
                    opcode, block_num = struct.unpack('>HH', data[:4])
                    
                    if opcode != OPCODE_DATA:
                        print(f"Expected DATA packet, got opcode {opcode}")
                        data_socket.close()
                        return
                        
                    if block_num != expected_block:
                        print(f"Expected block {expected_block}, got {block_num}")
                        data_socket.close()
                        return
                        
                    # Write data to file
                    file_data = data[4:]
                    f.write(file_data)
                    
                    # Send ACK
                    ack_packet = struct.pack('>HH', OPCODE_ACK, block_num)
                    data_socket.sendto(ack_packet, client_addr)
                    
                    # Check if this is the last packet
                    if len(file_data) < DEFAULT_BLOCK_SIZE:
                        break
                        
                    expected_block += 1
                    
            data_socket.close()
            print(f"File received successfully from {client_addr}")
            
        except Exception as e:
            print(f"Error receiving file: {e}")
            self.send_error(client_addr, ERROR_NOT_DEFINED, "File receive error")
            
    def wait_for_ack_from_socket(self, sock: socket.socket, block_num: int, client_addr: Tuple[str, int]) -> bool:
        """Wait for ACK packet from specific socket with timeout"""
        sock.settimeout(DEFAULT_TIMEOUT)
        try:
            data, addr = sock.recvfrom(MAX_PACKET_SIZE)
            if addr != client_addr:
                return False
                
            if len(data) < 4:
                return False
                
            opcode, ack_block = struct.unpack('>HH', data[:4])
            return opcode == OPCODE_ACK and ack_block == block_num
            
        except socket.timeout:
            return False
        finally:
            sock.settimeout(None)
            
    def send_error(self, client_addr: Tuple[str, int], error_code: int, error_msg: str):
        """Send error packet to client"""
        try:
            error_packet = struct.pack('>HH', OPCODE_ERROR, error_code)
            error_packet += error_msg.encode('ascii') + b'\x00'
            self.socket.sendto(error_packet, client_addr)
        except Exception as e:
            print(f"Error sending error packet: {e}")

def main():
    """Main function to run TFTP server"""
    parser = argparse.ArgumentParser(description='Simple TFTP Server')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=69, help='Server port')
    parser.add_argument('--root-dir', default='./files', help='Root directory for files')
    
    args = parser.parse_args()
    
    server = SimpleTFTPServer(args.host, args.port, args.root_dir)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()

if __name__ == '__main__':
    main()
