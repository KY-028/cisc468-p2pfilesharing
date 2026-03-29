"""
revocation.py — Key migration and revocation.

When a peer's identity key is compromised or rotated, they:
  1. Generate a new RSA-2048 key pair
  2. Sign the new public key with the OLD private key (proves ownership)
  3. Send REVOKE_KEY to all known contacts
  4. Contacts verify the cross-signature and update the stored key
  5. Contacts must re-verify the new fingerprint out-of-band

This module handles both sending and receiving key revocation events.

Reading order: Read keys.py and sign.py first, then this file.
"""

import os
import base64
import logging
import socket
import time
from typing import Optional
from app.core.state import app_state
from app.crypto.keys import (
    generate_rsa_keypair,
    serialize_public_key,
    save_private_key,
    load_private_key,
    get_fingerprint,
)
from app.crypto.sign import sign_data, verify_signature
from app.network.messages import revoke_key
from app.network.transport import send_message

logger = logging.getLogger(__name__)

# Path to identity key (same as main.py)
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
KEY_FILE = os.path.join(DATA_DIR, "identity_key.pem")
OLD_KEY_FILE = os.path.join(DATA_DIR, "identity_key.old.pem")


def rotate_key() -> dict:
    """
    Generate a new identity key pair and notify all known peers.

    Steps:
      1. Generate new RSA-2048 key pair
      2. Sign the new public key with the OLD private key
      3. Save the new key, archive the old key
      4. Update app_state with the new key
      5. Send REVOKE_KEY message to all known peers

    Returns:
        A dict with the rotation result:
        {
            "old_fingerprint": str,
            "new_fingerprint": str,
            "peers_notified": int,
            "errors": [str]
        }
    """
    result = {
        "old_fingerprint": app_state.fingerprint,
        "new_fingerprint": "",
        "peers_notified": 0,
        "errors": [],
    }

    # Get the old private key for cross-signing
    old_private_key = getattr(app_state, '_private_key', None)
    if not old_private_key:
        result["errors"].append("No existing private key found.")
        return result

    # Step 1: Generate new key pair
    new_private_key, new_public_key = generate_rsa_keypair()
    new_pub_pem = serialize_public_key(new_public_key)
    new_fingerprint = get_fingerprint(new_public_key)
    result["new_fingerprint"] = new_fingerprint

    # Step 2: Sign the new public key with the OLD private key
    # This proves that the holder of the old key authorized the rotation
    cross_signature = sign_data(old_private_key, new_pub_pem)

    # Step 3: Archive old key, save new key
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(KEY_FILE):
        # Keep one backup of the old key
        if os.path.exists(OLD_KEY_FILE):
            os.remove(OLD_KEY_FILE)
        os.rename(KEY_FILE, OLD_KEY_FILE)

    save_private_key(new_private_key, KEY_FILE)

    # Step 4: Update app_state
    app_state._private_key = new_private_key
    app_state._public_key = new_public_key
    app_state.public_key_pem = new_pub_pem.decode("utf-8")
    app_state.fingerprint = new_fingerprint

    logger.info(f"Key rotated: {result['old_fingerprint'][:16]}… → {new_fingerprint[:16]}…")
    app_state.add_status(
        f"Identity key rotated. New fingerprint: {new_fingerprint[:16]}…",
        level="success"
    )

    # Step 5: Notify all known peers
    for peer_id, peer in app_state.peers.items():
        try:
            _notify_peer_of_revocation(peer, new_pub_pem, cross_signature)
            result["peers_notified"] += 1
        except Exception as e:
            error_msg = f"Failed to notify {peer_id}: {e}"
            result["errors"].append(error_msg)
            logger.error(error_msg)

    app_state.add_status(
        f"Notified {result['peers_notified']}/{len(app_state.peers)} peers of key rotation.",
        level="info"
    )

    return result


def _notify_peer_of_revocation(peer, new_pub_pem: bytes,
                                 cross_signature: bytes) -> None:
    """Send a REVOKE_KEY message to a single peer."""
    msg = revoke_key(
        peer_id=app_state.peer_id,
        new_public_key=new_pub_pem,
        reason="key_rotation"
    )
    # Add the cross-signature to the payload so the peer can verify
    msg["payload"]["cross_signature"] = base64.b64encode(cross_signature).decode("ascii")
    msg["payload"]["old_fingerprint"] = getattr(app_state, '_old_fingerprint',
                                                 app_state.fingerprint)

    with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
        send_message(sock, msg)


def handle_revoke_key(msg: dict, sock, addr) -> None:
    """
    Handle an incoming REVOKE_KEY message from a peer.

    Verification steps:
      1. Look up the peer's current (old) public key
      2. Verify the cross-signature: old key signed the new key
      3. If valid, update the stored key and mark as untrusted
      4. Alert the user to re-verify the new fingerprint

    If we don't have the peer's old key, we can't verify — log a warning.
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    new_pub_pem_b64 = payload.get("new_public_key", "")
    cross_sig_b64 = payload.get("cross_signature", "")

    peer = app_state.peers.get(peer_id)
    if not peer:
        app_state.add_status(
            f"Received key revocation from unknown peer: {peer_id}",
            level="warning"
        )
        return

    # Decode the new public key
    try:
        if isinstance(new_pub_pem_b64, str) and not new_pub_pem_b64.startswith("-----"):
            new_pub_pem = base64.b64decode(new_pub_pem_b64)
        else:
            new_pub_pem = new_pub_pem_b64.encode("utf-8") if isinstance(new_pub_pem_b64, str) else new_pub_pem_b64
    except Exception:
        new_pub_pem = new_pub_pem_b64.encode("utf-8") if isinstance(new_pub_pem_b64, str) else new_pub_pem_b64

    # Verify cross-signature if we have the old key
    if peer.public_key_pem and cross_sig_b64:
        try:
            from app.crypto.keys import deserialize_public_key
            old_pub_key = deserialize_public_key(peer.public_key_pem)
            cross_sig = base64.b64decode(cross_sig_b64)
            valid = verify_signature(old_pub_key, new_pub_pem, cross_sig)

            if not valid:
                app_state.add_status(
                    f"⚠️ SECURITY ALERT: Key revocation from {peer_id} has "
                    f"INVALID cross-signature! This could be an attack.",
                    level="error"
                )
                logger.warning(f"Invalid cross-signature in REVOKE_KEY from {peer_id}")
                return

            app_state.add_status(
                f"Key revocation from {peer_id}: cross-signature verified ✓",
                level="info"
            )

        except Exception as e:
            app_state.add_status(
                f"Could not verify cross-signature from {peer_id}: {e}",
                level="warning"
            )
    else:
        app_state.add_status(
            f"Key revocation from {peer_id}: no old key to verify against.",
            level="warning"
        )

    # Update the peer's key (mark as untrusted until re-verified)
    from app.crypto.keys import deserialize_public_key as deser_pub
    try:
        new_pub_key = deser_pub(new_pub_pem)
        new_fingerprint = get_fingerprint(new_pub_key)
        peer.public_key_pem = new_pub_pem.decode("utf-8") if isinstance(new_pub_pem, bytes) else new_pub_pem
        peer.fingerprint = new_fingerprint
        peer.trusted = False  # Must re-verify!

        app_state.add_status(
            f"⚠️ Peer {peer_id} changed their key. New fingerprint: "
            f"{new_fingerprint[:16]}… — Please re-verify!",
            level="warning"
        )
    except Exception as e:
        app_state.add_status(
            f"Failed to process new key from {peer_id}: {e}",
            level="error"
        )
