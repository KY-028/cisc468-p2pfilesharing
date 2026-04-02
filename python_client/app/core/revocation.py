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

# Key file path is resolved dynamically from app_state so it always
# matches whichever data_{ip}_{port}/ directory _init_identity chose.


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
    logger.info(f"revocation.rotate_key → generating new RSA-2048 key, old fp={app_state.fingerprint[:16]}…")

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
    key_file = app_state.private_key_pem  # path set by _init_identity
    data_dir = os.path.dirname(key_file)
    old_key_file = os.path.join(data_dir, "identity_key.old.pem")
    os.makedirs(data_dir, exist_ok=True)
    if os.path.exists(key_file):
        # Keep one backup of the old key
        if os.path.exists(old_key_file):
            os.remove(old_key_file)
        os.rename(key_file, old_key_file)

    save_private_key(new_private_key, key_file)
    app_state.private_key_pem = key_file  # path unchanged after rotation

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

    # Invalidate all existing sessions (they were authenticated with the old key)
    from app.core.sessions import clear_all_sessions
    clear_all_sessions()
    app_state.add_status(
        "All active sessions cleared — new handshakes required.",
        level="info"
    )

    # Local trust reset after identity rotation:
    # - online peers must be re-verified (downgrade to untrusted)
    # - offline trusted placeholders are removed
    #   because trust can no longer be considered valid for the new key
    online_downgraded = 0
    offline_removed = 0
    from app.storage.manifests import clear_manifest
    peer_ids = set(app_state.peers.keys())
    app_state.pending_verifications = [
        pv for pv in app_state.pending_verifications
        if pv.get("peer_id") not in peer_ids
    ]
    for peer_id, peer in list(app_state.peers.items()):
        app_state.verify_confirmed_by_me.discard(peer_id)
        app_state.verify_confirmed_by_peer.discard(peer_id)

        if peer.online:
            if peer.trusted:
                online_downgraded += 1
            peer.trusted = False
        else:
            offline_removed += 1
            clear_manifest(peer_id)
            app_state.peers.pop(peer_id, None)

    app_state.save_trusted_peers()
    app_state.add_status(
        f"Local trust reset: {online_downgraded} online peer(s) marked unverified, "
        f"{offline_removed} offline peer(s) removed (manifests cleared).",
        level="warning"
    )

    # Step 5: Notify all known peers
    known_peers = list(app_state.peers.items())
    for peer_id, peer in known_peers:
        try:
            _notify_peer_of_revocation(peer, new_pub_pem, cross_signature)
            result["peers_notified"] += 1
        except Exception as e:
            error_msg = f"Failed to notify {peer_id}: {e}"
            result["errors"].append(error_msg)
            logger.error(error_msg)

    app_state.add_status(
        f"Notified {result['peers_notified']}/{len(known_peers)} peers of key rotation.",
        level="info"
    )

    return result


def _notify_peer_of_revocation(peer, new_pub_pem: bytes,
                                 cross_signature: bytes) -> None:
    """Send a REVOKE_KEY message to a single peer."""
    logger.info(f"revocation._notify_peer → sending REVOKE_KEY to {peer.peer_id} at {peer.address}:{peer.port}")
    msg = revoke_key(
        peer_id=app_state.peer_id,
        new_public_key=new_pub_pem,
        reason="key_rotation"
    )
    # The protocol layer automatically encodes bytes fields
    msg["payload"]["cross_signature"] = cross_signature
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
    logger.info(f"revocation.handle_revoke_key ← key revocation from {peer_id}, verifying cross-signature")
    new_pub_pem = payload.get("new_public_key", b"")
    cross_sig = payload.get("cross_signature", b"")

    peer = app_state.peers.get(peer_id)
    if not peer:
        app_state.add_status(
            f"Received key revocation from unknown peer: {peer_id}",
            level="warning"
        )
        return

    # Verify cross-signature if we have the old key
    if peer.public_key_pem and cross_sig:
        try:
            from app.crypto.keys import deserialize_public_key
            old_pub_key = deserialize_public_key(peer.public_key_pem)
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
        peer.public_key_pem = new_pub_pem.decode("utf-8")
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

    # Invalidate the existing session with this peer
    from app.core.sessions import remove_session
    remove_session(peer_id)
