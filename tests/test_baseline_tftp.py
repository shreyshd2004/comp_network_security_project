#!/usr/bin/env python3
"""
Test script for baseline TFTP implementation
Tests basic functionality and error conditions
"""

import os
import sys
import time
import subprocess
import threading
from pathlib import Path

# Add the baseline_tftp directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'baseline_tftp'))

from tftp_client import TFTPClient

class TFTPServerProcess:
    def __init__(self, host='localhost', port=6969, root_dir='./test_files'):
        self.host = host
        self.port = port
        self.root_dir = root_dir
        self.process = None
        
    def start(self):
        """Start the TFTP server process"""
        server_script = os.path.join(os.path.dirname(__file__), 'baseline_tftp', 'tftp_server.py')
        cmd = [sys.executable, server_script, '--host', self.host, '--port', str(self.port), '--root-dir', self.root_dir]
        
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)  # Give server time to start
        
        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            print(f"Server failed to start: {stderr.decode()}")
            return False
            
        print(f"TFTP server started on {self.host}:{self.port}")
        return True
        
    def stop(self):
        """Stop the TFTP server process"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            print("TFTP server stopped")

def create_test_files(test_dir):
    """Create test files for TFTP testing"""
    os.makedirs(test_dir, exist_ok=True)
    
    # Create various test files
    test_files = {
        'small.txt': 'Hello, TFTP!',
        'medium.txt': 'This is a medium-sized file for testing TFTP transfers.\n' * 50,
        'large.txt': 'This is a large file for testing TFTP transfers with multiple blocks.\n' * 200,
        'binary.bin': bytes(range(256)) * 10,  # Binary data
    }
    
    for filename, content in test_files.items():
        filepath = os.path.join(test_dir, filename)
        if isinstance(content, str):
            with open(filepath, 'w') as f:
                f.write(content)
        else:
            with open(filepath, 'wb') as f:
                f.write(content)
        print(f"Created test file: {filename} ({len(content)} bytes)")

def test_basic_transfer(client, test_dir):
    """Test basic file transfer operations"""
    print("\n=== Testing Basic File Transfers ===")
    
    # Test downloading a file
    print("Testing file download...")
    success = client.get_file('small.txt', os.path.join(test_dir, 'downloaded_small.txt'))
    if success:
        print("✓ File download successful")
    else:
        print("✗ File download failed")
        return False
        
    # Test uploading a file
    print("Testing file upload...")
    upload_file = os.path.join(test_dir, 'upload_test.txt')
    with open(upload_file, 'w') as f:
        f.write("This is a test file for upload.")
        
    success = client.put_file(upload_file, 'uploaded_test.txt')
    if success:
        print("✓ File upload successful")
    else:
        print("✗ File upload failed")
        return False
        
    return True

def test_error_conditions(client, test_dir):
    """Test error handling"""
    print("\n=== Testing Error Conditions ===")
    
    # Test downloading non-existent file
    print("Testing download of non-existent file...")
    success = client.get_file('nonexistent.txt')
    if not success:
        print("✓ Correctly handled non-existent file")
    else:
        print("✗ Should have failed for non-existent file")
        return False
        
    # Test uploading to existing file (should fail)
    print("Testing upload to existing file...")
    existing_file = os.path.join(test_dir, 'small.txt')
    success = client.put_file(existing_file, 'small.txt')  # Try to overwrite
    if not success:
        print("✓ Correctly prevented overwriting existing file")
    else:
        print("✗ Should have failed to overwrite existing file")
        return False
        
    return True

def test_different_file_sizes(client, test_dir):
    """Test transfers of different file sizes"""
    print("\n=== Testing Different File Sizes ===")
    
    files_to_test = ['small.txt', 'medium.txt', 'large.txt', 'binary.bin']
    
    for filename in files_to_test:
        print(f"Testing {filename}...")
        download_path = os.path.join(test_dir, f'downloaded_{filename}')
        
        success = client.get_file(filename, download_path)
        if success:
            # Verify file integrity
            original_path = os.path.join(test_dir, filename)
            if os.path.exists(original_path) and os.path.exists(download_path):
                with open(original_path, 'rb') as f1, open(download_path, 'rb') as f2:
                    if f1.read() == f2.read():
                        print(f"✓ {filename} transfer successful and verified")
                    else:
                        print(f"✗ {filename} transfer failed verification")
                        return False
            else:
                print(f"✗ {filename} files not found for verification")
                return False
        else:
            print(f"✗ {filename} transfer failed")
            return False
            
    return True

def run_performance_test(client, test_dir):
    """Run basic performance test"""
    print("\n=== Performance Test ===")
    
    # Test with large file
    large_file = 'large.txt'
    download_path = os.path.join(test_dir, 'perf_test_download.txt')
    
    start_time = time.time()
    success = client.get_file(large_file, download_path)
    end_time = time.time()
    
    if success:
        file_size = os.path.getsize(os.path.join(test_dir, large_file))
        duration = end_time - start_time
        throughput = file_size / duration if duration > 0 else 0
        
        print(f"✓ Large file transfer completed")
        print(f"  File size: {file_size} bytes")
        print(f"  Duration: {duration:.2f} seconds")
        print(f"  Throughput: {throughput:.2f} bytes/second")
        return True
    else:
        print("✗ Performance test failed")
        return False

def main():
    """Main test function"""
    print("TFTP Baseline Implementation Test Suite")
    print("=" * 50)
    
    # Setup
    test_dir = './test_files'
    server_dir = './test_files'
    
    # Create test files
    print("Creating test files...")
    create_test_files(test_dir)
    
    # Start TFTP server
    print("\nStarting TFTP server...")
    server = TFTPServerProcess(root_dir=server_dir)
    if not server.start():
        print("Failed to start TFTP server")
        return 1
        
    try:
        # Create TFTP client
        client = TFTPClient('localhost', 6969)
        
        # Run tests
        tests_passed = 0
        total_tests = 4
        
        if test_basic_transfer(client, test_dir):
            tests_passed += 1
            
        if test_error_conditions(client, test_dir):
            tests_passed += 1
            
        if test_different_file_sizes(client, test_dir):
            tests_passed += 1
            
        if run_performance_test(client, test_dir):
            tests_passed += 1
            
        # Results
        print("\n" + "=" * 50)
        print(f"Test Results: {tests_passed}/{total_tests} tests passed")
        
        if tests_passed == total_tests:
            print("✓ All tests passed! Baseline TFTP implementation is working correctly.")
            return 0
        else:
            print("✗ Some tests failed. Check the implementation.")
            return 1
            
    finally:
        server.stop()

if __name__ == '__main__':
    sys.exit(main())
