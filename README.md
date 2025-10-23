# Secure TFTP (sTFTP) Project

This project implements a secure version of the Trivial File Transfer Protocol (TFTP) that addresses security vulnerabilities while maintaining efficiency for resource-constrained devices.

## Project Structure

- `baseline_tftp/` - Basic TFTP implementation for comparison
- `tests/` - Test files and validation scripts
- `docs/` - Documentation and analysis

## Baseline TFTP Implementation

The baseline implementation includes:
- Basic TFTP server with read/write operations
- TFTP client for testing
- Standard TFTP error handling
- UDP-based communication on port 69

## Usage

### Running the Baseline TFTP Server
```bash
cd baseline_tftp
python tftp_server.py
```

### Testing with TFTP Client
```bash
cd baseline_tftp
python tftp_client.py
```

### Running demo_tftp_secure.py
Use this command `python demo_tftp_secure.py --only secure \
  --psk 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f`

Make sure you have cryptography library installed in your environment. If not you can rune pip install cryptography

## Requirements

- Python 3.7+
- No external dependencies for baseline implementation
