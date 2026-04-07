# CISC 468 — Secure P2P File Sharing Application

A Python-based secure peer-to-peer file sharing system with a localhost web UI, built for the CISC 468 course project.

## Features

- **Peer Discovery**: mDNS-based LAN discovery via zeroconf
- **Authentication**: RSA-2048 identity keys with challenge-response
- **Confidentiality**: AES-256-CTR encryption with HMAC-SHA256 integrity (Encrypt-then-MAC)
- **Forward Secrecy**: Ephemeral ECDH session keys
- **Consent**: All file transfers require explicit user approval
- **Third-Party Verification**: Verify files from any peer using the original owner's signature
- **Secure Storage**: Encrypted local vault with PBKDF2-derived keys

## Quick Start

```bash
# 1. Navigate to the Python client
cd python_client

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python -m app.main

# 5. Open in your browser
#    → http://localhost:5001
```

## Running Tests

```bash
cd python_client
pytest app/tests/ -v
```

## C# Client

Usually you would have to build the C# client from source located in the `cs_client/P2PFT_Cs` directory, but for convenience, we have included a pre-built executable in the `cs_client` directory. To run the C# client, simply navigate to the `cs_client` directory and execute the `.exe` file directly.
