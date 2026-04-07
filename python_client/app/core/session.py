"""
session.py — Station-to-Station (STS) Protocol session management.

This module implements the STS handshake, which achieves:
  1. Mutual authentication (both peers prove identity via RSA signatures)
  2. Perfect forward secrecy (ephemeral ECDH keys, discarded after use)

in a single 3-message exchange.

Handshake flow:
  1. Alice → Bob:  KEY_EXCHANGE_INIT    (alice_ephemeral_pub)
  2. Bob → Alice:  KEY_EXCHANGE_RESPONSE (bob_ephemeral_pub, bob_long_term_pub,
                                          Sig_Bob(bob_eph || alice_eph))
  3. Alice → Bob:  KEY_EXCHANGE_CONFIRM  (alice_long_term_pub,
                                          Sig_Alice(alice_eph || bob_eph))

After all three messages, both sides compute the same ECDH shared secret,
derive a session key via HKDF, and discard the ephemeral keys.

Reading order: Read keys.py, sign.py, kdf.py first, then this file.
"""

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from app.crypto.sign import sign_data, verify_signature
from app.crypto.kdf import hkdf_derive_key




def generate_ephemeral_keypair():
    """
    Generate a fresh ECDH key pair on the P-256 curve.

    These keys are ephemeral — used for ONE session, then discarded.
    This gives us perfect forward secrecy: even if the long-term RSA
    key is later compromised, past session keys can't be recovered.

    Returns:
        (private_key, public_key) — EC key objects on SECP256R1.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_ec_public_key(public_key) -> bytes:
    """Serialize an EC public key to uncompressed point bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def deserialize_ec_public_key(point_bytes: bytes):
    """Deserialize uncompressed point bytes to an EC public key."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), point_bytes,
    )


def compute_shared_secret(our_private_key, their_public_key) -> bytes:
    """
    Perform ECDH key agreement.

    Args:
        our_private_key: Our ephemeral EC private key.
        their_public_key: The other peer's ephemeral EC public key.

    Returns:
        The raw shared secret bytes (32 bytes for P-256).
    """
    return our_private_key.exchange(ec.ECDH(), their_public_key)



class STSSession:
    """
    Manages the state of an STS handshake.

    There are two roles:
      - INITIATOR (Alice): creates the session, sends init, receives response,
        sends confirm, derives key.
      - RESPONDER (Bob): receives init, sends response, receives confirm,
        derives key.

    Usage (Initiator):
        session = STSSession(our_rsa_private, our_rsa_public)
        init_msg_payload = session.create_init()
        # ... send init, receive response ...
        confirm_payload = session.handle_response(response_payload)
        # ... send confirm ...
        session_key = session.session_key  # ready to use

    Usage (Responder):
        session = STSSession(our_rsa_private, our_rsa_public)
        response_payload = session.handle_init(init_payload)
        # ... send response, receive confirm ...
        session.handle_confirm(confirm_payload)
        session_key = session.session_key  # ready to use
    """

    def __init__(self, rsa_private_key, rsa_public_key):
        """
        Args:
            rsa_private_key: Our long-term RSA private key (for signing).
            rsa_public_key: Our long-term RSA public key (to send to peer).
        """
        self.rsa_private_key = rsa_private_key
        self.rsa_public_key = rsa_public_key

       
        self._ecdh_private, self._ecdh_public = generate_ephemeral_keypair()

    
        self.peer_ecdh_public = None
        self.peer_rsa_public = None

       
        self.session_key = None

      
        self.role = None       
        self.complete = False

 
    @property
    def our_ephemeral_pub_bytes(self) -> bytes:
        return serialize_ec_public_key(self._ecdh_public)

  

    def create_init(self) -> dict:
        """
        Step 1 (Initiator): Create the KEY_EXCHANGE_INIT payload.

        Returns:
            dict with 'ephemeral_public_key' (bytes).
        """
        self.role = "initiator"
        return {
            "ephemeral_public_key": self.our_ephemeral_pub_bytes,
        }

    def handle_response(self, payload: dict) -> dict:
        """
        Step 2 (Initiator): Process the responder's KEY_EXCHANGE_RESPONSE
        and create the KEY_EXCHANGE_CONFIRM payload.

        Verifies Bob's signature over (bob_eph || alice_eph) using Bob's
        long-term RSA public key.

        Args:
            payload: dict with 'ephemeral_public_key', 'long_term_public_key',
                     and 'signature' (all as bytes).

        Returns:
            dict payload for KEY_EXCHANGE_CONFIRM.

        Raises:
            ValueError: If Bob's signature is invalid.
        """
        from app.crypto.keys import deserialize_public_key

      
        peer_eph_bytes = payload["ephemeral_public_key"]
        self.peer_ecdh_public = deserialize_ec_public_key(peer_eph_bytes)
        self.peer_rsa_public = deserialize_public_key(payload["long_term_public_key"])

    
        signed_data = peer_eph_bytes + self.our_ephemeral_pub_bytes
        if not verify_signature(self.peer_rsa_public, signed_data,
                                payload["signature"]):
            raise ValueError("STS handshake failed: responder signature invalid")

     
        shared_secret = compute_shared_secret(self._ecdh_private,
                                              self.peer_ecdh_public)
        self.session_key = hkdf_derive_key(shared_secret)
        self.complete = True

    
        our_signed_data = self.our_ephemeral_pub_bytes + peer_eph_bytes
        from app.crypto.keys import serialize_public_key
        return {
            "long_term_public_key": serialize_public_key(self.rsa_public_key),
            "signature": sign_data(self.rsa_private_key, our_signed_data),
        }

 

    def handle_init(self, payload: dict) -> dict:
        """
        Step 1 (Responder): Process the initiator's KEY_EXCHANGE_INIT
        and create the KEY_EXCHANGE_RESPONSE payload.

        Args:
            payload: dict with 'ephemeral_public_key' (bytes).

        Returns:
            dict payload for KEY_EXCHANGE_RESPONSE.
        """
        self.role = "responder"

   
        peer_eph_bytes = payload["ephemeral_public_key"]
        self.peer_ecdh_public = deserialize_ec_public_key(peer_eph_bytes)

   
        signed_data = self.our_ephemeral_pub_bytes + peer_eph_bytes
        from app.crypto.keys import serialize_public_key
        return {
            "ephemeral_public_key": self.our_ephemeral_pub_bytes,
            "long_term_public_key": serialize_public_key(self.rsa_public_key),
            "signature": sign_data(self.rsa_private_key, signed_data),
        }

    def handle_confirm(self, payload: dict) -> None:
        """
        Step 3 (Responder): Process the initiator's KEY_EXCHANGE_CONFIRM.

        Verifies Alice's signature and derives the session key.

        Args:
            payload: dict with 'long_term_public_key' and 'signature' (bytes).

        Raises:
            ValueError: If Alice's signature is invalid.
        """
        from app.crypto.keys import deserialize_public_key

    
        self.peer_rsa_public = deserialize_public_key(payload["long_term_public_key"])

     
        peer_eph_bytes = serialize_ec_public_key(self.peer_ecdh_public)
        signed_data = peer_eph_bytes + self.our_ephemeral_pub_bytes
        if not verify_signature(self.peer_rsa_public, signed_data,
                                payload["signature"]):
            raise ValueError("STS handshake failed: initiator signature invalid")

    
        shared_secret = compute_shared_secret(self._ecdh_private,
                                              self.peer_ecdh_public)
        self.session_key = hkdf_derive_key(shared_secret)
        self.complete = True


    def destroy(self) -> None:
        """
        Wipe ephemeral key material from memory.

        Call this after the session is no longer needed to limit
        window of exposure. (Python doesn't guarantee secure erasure,
        but this is a best-effort cleanup.)
        """
        self._ecdh_private = None
        self._ecdh_public = None
        self.session_key = None
        self.complete = False
