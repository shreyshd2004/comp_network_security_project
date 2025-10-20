#!/usr/bin/env python3
"""
Simple demo script for baseline TFTP implementation
Demonstrates basic usage of the TFTP server and client
"""

import os
import sys
import time
import subprocess
import threading

# Add the baseline_tftp directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'baseline_tftp'))

from tftp_client import TFTPClient

def create_demo_files():
    """Create demo files for the TFTP demonstration"""
    demo_dir = './demo_files'
    os.makedirs(demo_dir, exist_ok=True)
    
    # Create some demo files
    demo_files = {
        'readme.txt': '''Welcome to the TFTP Demo!

This is a demonstration of the baseline TFTP implementation.
TFTP (Trivial File Transfer Protocol) is a simple protocol for
transferring files over UDP.

Features demonstrated:
- File downloads (GET)
- File uploads (PUT)
- Error handling
- Binary file transfers

This implementation follows RFC 1350 specifications.
''',
        'config.json': '''{
    "server": {
        "host": "localhost",
        "port": 69,
        "timeout": 5
    },
    "client": {
        "block_size": 512,
        "mode": "octet"
    }
}''',
        'data.bin': bytes([i % 256 for i in range(1024)])  # 1KB of test data
    }
    
    print("Creating demo files...")
    for filename, content in demo_files.items():
        filepath = os.path.join(demo_dir, filename)
        if isinstance(content, str):
            with open(filepath, 'w') as f:
                f.write(content)
        else:
            with open(filepath, 'wb') as f:
                f.write(content)
        print(f"  Created: {filename} ({len(content)} bytes)")
    
    return demo_dir

def start_server(server_dir):
    """Start the TFTP server in a separate process"""
    server_script = os.path.join(os.path.dirname(__file__), 'baseline_tftp', 'tftp_server.py')
    cmd = [sys.executable, server_script, '--host', 'localhost', '--port', '6969', '--root-dir', server_dir]
    
    print(f"Starting TFTP server with root directory: {server_dir}")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Give server time to start
    time.sleep(1)
    
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        print(f"Server failed to start: {stderr.decode()}")
        return None
    
    print("✓ TFTP server started successfully")
    return process

def demo_file_download(client, filename):
    """Demonstrate file download"""
    print(f"\n--- Downloading {filename} ---")
    
    download_path = f'downloaded_{filename}'
    success = client.get_file(filename, download_path)
    
    if success:
        print(f"✓ Successfully downloaded {filename}")
        
        # Show file contents for text files
        if filename.endswith('.txt') or filename.endswith('.json'):
            print(f"\nContents of {filename}:")
            print("-" * 40)
            try:
                with open(download_path, 'r') as f:
                    print(f.read())
            except:
                print("(Could not display contents)")
            print("-" * 40)
    else:
        print(f"✗ Failed to download {filename}")
    
    return success

def demo_file_upload(client, local_file, remote_name):
    """Demonstrate file upload"""
    print(f"\n--- Uploading {local_file} as {remote_name} ---")
    
    if not os.path.exists(local_file):
        print(f"✗ Local file {local_file} not found")
        return False
    
    success = client.put_file(local_file, remote_name)
    
    if success:
        print(f"✓ Successfully uploaded {local_file} as {remote_name}")
    else:
        print(f"✗ Failed to upload {local_file}")
    
    return success

def demo_error_handling(client):
    """Demonstrate error handling"""
    print(f"\n--- Testing Error Handling ---")
    
    # Try to download non-existent file
    print("Attempting to download non-existent file...")
    success = client.get_file('nonexistent_file.txt')
    if not success:
        print("✓ Correctly handled non-existent file error")
    else:
        print("✗ Should have failed for non-existent file")
    
    # Try to upload to existing file
    print("Attempting to overwrite existing file...")
    success = client.put_file('readme.txt', 'readme.txt')  # Try to overwrite
    if not success:
        print("✓ Correctly prevented file overwrite")
    else:
        print("✗ Should have failed to overwrite existing file")

def main():
    """Main demo function"""
    print("TFTP Baseline Implementation Demo")
    print("=" * 50)
    
    # Create demo files
    demo_dir = create_demo_files()
    
    # Start server
    server_process = start_server(demo_dir)
    if not server_process:
        return 1
    
    try:
        # Create client
        client = TFTPClient('localhost', 6969)
        
        # Demo file downloads
        files_to_download = ['readme.txt', 'config.json', 'data.bin']
        for filename in files_to_download:
            demo_file_download(client, filename)
            time.sleep(0.5)  # Small delay between requests
        
        # Demo file upload
        upload_file = os.path.join(demo_dir, 'readme.txt')
        demo_file_upload(client, upload_file, 'uploaded_readme.txt')
        time.sleep(0.5)  # Small delay between requests
        
        # Demo error handling
        demo_error_handling(client)
        
        # Summary
        print(f"\n" + "=" * 50)
        print("Demo completed!")
        print("\nKey features demonstrated:")
        print("• File downloads (GET operations)")
        print("• File uploads (PUT operations)")
        print("• Binary file transfers")
        print("• Error handling")
        print("• RFC 1350 compliance")
        
        print(f"\nFiles created in demo:")
        print(f"• Server files: {demo_dir}/")
        print(f"• Downloaded files: ./downloaded_*")
        
    finally:
        # Stop server
        print(f"\nStopping TFTP server...")
        server_process.terminate()
        server_process.wait()
        print("✓ Server stopped")

if __name__ == '__main__':
    main()
