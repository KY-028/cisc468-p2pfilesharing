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

C#
Extract Cs_Client_ready_to_run.rar, run setup.exe
## Running Tests

```bash
cd python_client
pytest app/tests/ -v
```

## Project Structure

```
python_client/
├── app/
│   ├── main.py              # Flask entry point
│   ├── core/
│   │   ├── protocol.py      # Message schema & validation
│   │   ├── session.py        # Ephemeral session management
│   │   ├── consent.py        # Consent flow management
│   │   └── state.py          # In-memory application state
│   ├── ui/
│   │   ├── routes.py         # Flask routes & API endpoints
│   │   ├── templates/        # Jinja2 HTML templates
│   │   └── static/           # CSS & JavaScript
│   ├── crypto/
│   │   ├── keys.py           # RSA key generation & fingerprints
│   │   ├── sign.py           # Digital signatures (RSA-PSS)
│   │   ├── encrypt.py        # AES-256-CTR encryption
│   │   ├── mac.py            # HMAC-SHA256 integrity
│   │   ├── kdf.py            # Key derivation (PBKDF2)
│   │   └── hashing.py        # SHA-256 hashing utilities
│   ├── network/
│   │   ├── discovery.py      # mDNS peer discovery
│   │   ├── transport.py      # TCP socket transport
│   │   └── messages.py       # Message builder functions
│   ├── storage/
│   │   ├── vault.py          # Encrypted local storage
│   │   ├── files.py          # Local file management
│   │   └── manifests.py      # File manifest metadata
│   └── tests/
│       ├── test_protocol.py  # Protocol unit tests
│       ├── test_crypto.py    # Crypto unit tests
│       ├── test_storage.py   # Storage unit tests
│       └── test_errors.py    # Error handling tests
├── requirements.txt
├── protocol_spec.md          # Protocol specification
└── README.md
```

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Local app shell & UI | ✅ Complete |
| 2 | Protocol & message format | ✅ Complete |
| 3 | Identity, keys, authentication | ⬜ Planned |
| 4 | mDNS peer discovery | ⬜ Planned |
| 5 | File list sharing | ⬜ Planned |
| 6 | Consent-based file transfer | ⬜ Planned |
| 7 | AES encryption + HMAC integrity | ⬜ Planned |
| 8 | Perfect forward secrecy (ECDH) | ⬜ Planned |
| 9 | Third-party file verification | ⬜ Planned |
| 10 | Key migration & revocation | ⬜ Planned |
| 11 | Secure local storage (vault) | ⬜ Planned |
| 12 | Error handling & tests | ⬜ Planned |

## Technology Stack

- **Backend**: Flask
- **Frontend**: HTML / CSS / Vanilla JS
- **Crypto**: `cryptography` library
- **Discovery**: `zeroconf`
- **Testing**: `pytest`
