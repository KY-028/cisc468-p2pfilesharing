"""
sign.py — RSA-PSS digital signature creation and verification.

RSA-PSS (Probabilistic Signature Scheme) is the recommended padding
for RSA signatures. We use SHA-256 as the hash algorithm and set the
salt length to the maximum allowed value.

Reading order: Read keys.py first, then this file.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature


# Standard PSS padding config used for all signatures in this app.
_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def sign_data(private_key, data: bytes) -> bytes:
    """
    Create an RSA-PSS signature over the given data.

    Args:
        private_key: RSAPrivateKey object (the signer's long-term key).
        data: The bytes to sign.

    Returns:
        The signature as raw bytes.
    """
    return private_key.sign(
        data,
        _PSS_PADDING,
        hashes.SHA256(),
    )


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """
    Verify an RSA-PSS signature.

    Returns True if the signature is valid, False otherwise.
    Never raises an exception for invalid signatures — this makes
    callers simpler (they just check the bool).

    Args:
        public_key: RSAPublicKey object (the alleged signer's key).
        data: The original data that was signed.
        signature: The signature bytes to verify.

    Returns:
        True if valid, False if invalid or any error occurs.
    """
    try:
        public_key.verify(
            signature,
            data,
            _PSS_PADDING,
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Catch any other crypto errors (e.g., wrong key type)
        return False
