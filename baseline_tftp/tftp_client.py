#!/usr/bin/env python3
"""
Basic TFTP Client Implementation
RFC 1350 compliant TFTP client for testing the baseline server
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

class TFTPClient:
    def __init__(self, server_host='localhost', server_port=69):
        self.server_host = server_host
        self.server_port = server_port
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
        if not self.socket:
            self.connect()
            
        if local_filename is None:
            local_filename = remote_filename
            
        try:
            # Create RRQ packet
            rrq_packet = struct.pack('>H', OPCODE_RRQ)
            rrq_packet += remote_filename.encode('ascii') + b'\x00'
            rrq_packet += b'octet\x00'
            
            # Send RRQ
            self.socket.sendto(rrq_packet, (self.server_host, self.server_port))
            
            # Receive file
            with open(local_filename, 'wb') as f:
                expected_block = 1
                
                while True:
                    # Receive DATA packet
                    data, addr = self.socket.recvfrom(MAX_PACKET_SIZE)
                    
                    if len(data) < 4:
                        print("Invalid packet received")
                        return False
                        
                    opcode, block_num = struct.unpack('>HH', data[:4])
                    
                    if opcode == OPCODE_ERROR:
                        error_code, error_msg = self.parse_error(data)
                        print(f"Server error {error_code}: {error_msg}")
                        return False
                        
                    if opcode != OPCODE_DATA:
                        print(f"Expected DATA packet, got opcode {opcode}")
                        return False
                        
                    if block_num != expected_block:
                        print(f"Expected block {expected_block}, got {block_num}")
                        return False
                        
                    # Write data to file
                    file_data = data[4:]
                    f.write(file_data)
                    
                    # Send ACK
                    ack_packet = struct.pack('>HH', OPCODE_ACK, block_num)
                    self.socket.sendto(ack_packet, addr)
                    
                    # Check if this is the last packet
                    if len(file_data) < DEFAULT_BLOCK_SIZE:
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
            
    def put_file(self, local_filename: str, remote_filename: str = None) -> bool:
        """Upload a file to the TFTP server"""
        if not self.socket:
            self.connect()
            
        if remote_filename is None:
            remote_filename = local_filename
            
        if not os.path.exists(local_filename):
            print(f"Local file not found: {local_filename}")
            return False
            
        try:
            # Create WRQ packet
            wrq_packet = struct.pack('>H', OPCODE_WRQ)
            wrq_packet += remote_filename.encode('ascii') + b'\x00'
            wrq_packet += b'octet\x00'
            
            # Send WRQ
            self.socket.sendto(wrq_packet, (self.server_host, self.server_port))
            
            # Wait for initial ACK
            data, addr = self.socket.recvfrom(MAX_PACKET_SIZE)
            
            if len(data) < 4:
                print("Invalid packet received")
                return False
                
            opcode, ack_block = struct.unpack('>HH', data[:4])
            
            if opcode == OPCODE_ERROR:
                error_code, error_msg = self.parse_error(data)
                print(f"Server error {error_code}: {error_msg}")
                return False
                
            if opcode != OPCODE_ACK or ack_block != 0:
                print(f"Expected initial ACK, got opcode {opcode}, block {ack_block}")
                return False
                
            # Send file
            with open(local_filename, 'rb') as f:
                block_num = 1
                
                while True:
                    data = f.read(DEFAULT_BLOCK_SIZE)
                    if not data:
                        break
                        
                    # Create DATA packet
                    packet = struct.pack('>HH', OPCODE_DATA, block_num) + data
                    
                    # Send packet
                    self.socket.sendto(packet, addr)
                    
                    # Wait for ACK
                    ack_data, ack_addr = self.socket.recvfrom(MAX_PACKET_SIZE)
                    
                    if len(ack_data) < 4:
                        print("Invalid ACK packet received")
                        return False
                        
                    ack_opcode, ack_block = struct.unpack('>HH', ack_data[:4])
                    
                    if ack_opcode == OPCODE_ERROR:
                        error_code, error_msg = self.parse_error(ack_data)
                        print(f"Server error {error_code}: {error_msg}")
                        return False
                        
                    if ack_opcode != OPCODE_ACK or ack_block != block_num:
                        print(f"Expected ACK {block_num}, got opcode {ack_opcode}, block {ack_block}")
                        return False
                        
                    block_num += 1
                    
                # Send empty DATA packet to signal end
                packet = struct.pack('>HH', OPCODE_DATA, block_num) + b''
                self.socket.sendto(packet, addr)
                
                # Wait for final ACK
                final_ack, final_addr = self.socket.recvfrom(MAX_PACKET_SIZE)
                
                if len(final_ack) < 4:
                    print("Invalid final ACK packet received")
                    return False
                    
                final_opcode, final_block = struct.unpack('>HH', final_ack[:4])
                
                if final_opcode == OPCODE_ERROR:
                    error_code, error_msg = self.parse_error(final_ack)
                    print(f"Server error {error_code}: {error_msg}")
                    return False
                    
                if final_opcode != OPCODE_ACK or final_block != block_num:
                    print(f"Expected final ACK {block_num}, got opcode {final_opcode}, block {final_block}")
                    return False
                    
            print(f"File uploaded successfully: {remote_filename}")
            return True
            
        except socket.timeout:
            print("Timeout waiting for server response")
            return False
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
            
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
    parser = argparse.ArgumentParser(description='Basic TFTP Client')
    parser.add_argument('--server', default='localhost', help='TFTP server host')
    parser.add_argument('--port', type=int, default=69, help='TFTP server port')
    parser.add_argument('action', choices=['get', 'put'], help='Action: get or put')
    parser.add_argument('filename', help='Filename')
    parser.add_argument('--local', help='Local filename (for put action)')
    
    args = parser.parse_args()
    
    client = TFTPClient(args.server, args.port)
    
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
