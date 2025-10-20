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

## Requirements

- Python 3.7+
- No external dependencies for baseline implementation
