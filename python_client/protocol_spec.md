# Protocol Specification — CISC 468 P2P Secure File Sharing

## 1. Overview

This document defines the protocol used for peer-to-peer communication in the CISC 468 Secure File Sharing application. All messages are JSON-encoded and exchanged over TCP sockets with a 4-byte big-endian length prefix.

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Identity keys | RSA-2048 | Widely understood; easy to explain |
| Signatures | RSA-PSS + SHA-256 | Standard, secure padding scheme |
| Auth + PFS | STS Protocol (ECDH + RSA-PSS) | Mutual auth + PFS in one handshake |
| Encryption (in-transit) | **AES-256-GCM** (AEAD) | Confidentiality + integrity in one call |
| Encryption (at-rest) | AES-256-GCM | Consistent with in-transit |
| KDF (sessions) | HKDF-SHA256 | For high-entropy ECDH output |
| KDF (vault) | PBKDF2-HMAC-SHA256 (600K iter) | For low-entropy passwords |
| Transport | TCP sockets | Clean P2P separation from HTTP UI |
| Serialization | JSON + base64 for binary | Human-readable, debuggable |
| Discovery | mDNS via zeroconf | LAN peer discovery |

## 3. Message Format

Every message is a JSON object with four top-level fields:

```json
{
    "version": "1.0",
    "type": "MESSAGE_TYPE",
    "timestamp": 1711324800.0,
    "payload": { ... }
}
```

Binary fields (keys, signatures, ciphertext) are **base64-encoded** strings.

## 4. STS Handshake (Authentication + PFS)

```
Alice                                    Bob
  |                                        |
  |-- KEY_EXCHANGE_INIT ------------------>|
  |   (peer_id, ephemeral_public_key)      |
  |                                        |
  |<-- KEY_EXCHANGE_RESPONSE --------------|
  |   (peer_id, ephemeral_public_key,      |
  |    long_term_public_key,               |
  |    Sig_Bob(bob_eph || alice_eph))      |
  |                                        |
  |-- KEY_EXCHANGE_CONFIRM --------------->|
  |   (peer_id, long_term_public_key,      |
  |    Sig_Alice(alice_eph || bob_eph))    |
  |                                        |
  |  Both derive shared_secret via ECDH    |
  |  Both derive session_key via HKDF      |
```

All three messages are exchanged on a **single TCP connection** (opened by the initiator). The session key is cached in `sessions._session_keys` for subsequent file transfers.

### 4.1 Session Lifecycle

- **Lazy establishment:** A session is created on-demand before the first file transfer to a peer (`sessions.initiate_handshake()`).
- **Key caching:** Once established, the 32-byte session key is reused for all file transfers with that peer.
- **Invalidation on key rotation:** When a peer rotates their identity key (`REVOKE_KEY`), all sessions with that peer are cleared. New handshakes use the new identity key.
- **Ephemeral keys discarded:** After the handshake, ECDH private keys are overwritten with `None` (best-effort in Python).

## 5. Message Types

| Type | Required Payload Fields |
|------|------------------------|
| PEER_ANNOUNCE | peer_id, port |
| PEER_LIST_REQUEST | peer_id |
| PEER_LIST_RESPONSE | peer_id, peers |
| KEY_EXCHANGE_INIT | peer_id, ephemeral_public_key |
| KEY_EXCHANGE_RESPONSE | peer_id, ephemeral_public_key, long_term_public_key, signature |
| KEY_EXCHANGE_CONFIRM | peer_id, long_term_public_key, signature |
| FILE_LIST_REQUEST | peer_id |
| FILE_LIST_RESPONSE | peer_id, files |
| FILE_REQUEST | peer_id, filename, file_hash |
| FILE_SEND | peer_id, filename, file_hash, data (AES-256-GCM encrypted) |
| CONSENT_REQUEST | peer_id, action, filename |
| CONSENT_RESPONSE | peer_id, request_id, approved |
| REVOKE_KEY | peer_id, new_public_key |
| ERROR | peer_id, code, description |

## 6. Wire Format (TCP)

```
[4 bytes: big-endian uint32 length] [N bytes: UTF-8 JSON]
```

### 6.1 Encrypted File Transfer Flow

```
Sender                                   Receiver
  |                                        |
  |  (STS handshake if no session exists)  |
  |  session_key = HKDF(ECDH_shared)       |
  |                                        |
  |  aad = "filename:sha256_hash"          |
  |  blob = AES-GCM(session_key, data, aad)|
  |                                        |
  |-- FILE_SEND (blob as base64) --------->|
  |                                        |
  |  Receiver decrypts with same           |
  |  session_key + aad, then verifies      |
  |  SHA-256 hash of the plaintext.        |
```

If decryption fails (`InvalidTag`), the file is rejected and the user sees a security alert.

## 7. Security Layers

| Layer | Mechanism | Module |
|-------|-----------|--------|
| Identity | RSA-2048 key pairs | `crypto/keys.py` |
| Authentication | STS Protocol (signed ECDH) | `core/session.py`, `core/sessions.py` |
| Forward Secrecy | Ephemeral ECDH (P-256), discarded after handshake | `core/session.py` |
| Confidentiality + Integrity (in-transit) | AES-256-GCM with AAD binding (filename:hash) | `crypto/encrypt.py`, `core/consent.py` |
| Session management | Lazy handshake, per-peer key caching, invalidation on rotation | `core/sessions.py` |
| At-rest encryption | AES-256-GCM + PBKDF2 (600K iterations) | `storage/vault.py` |
| Key migration | REVOKE_KEY + cross-signature + session invalidation | `core/revocation.py` |
