"""
test_crypto.py — Unit tests for the crypto and STS session modules.

Tests cover:
  - RSA key generation, serialization, and fingerprinting
  - RSA-PSS signing and verification
  - SHA-256 hashing
  - HKDF and PBKDF2 key derivation
  - Full STS handshake (both sides derive matching session keys)
  - STS handshake fails on tampered signatures

Run:  pytest app/tests/test_crypto.py -v
"""

import os
import tempfile
import pytest
from app.crypto.keys import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    save_private_key,
    load_private_key,
    get_fingerprint,
)
from app.crypto.sign import sign_data, verify_signature
from app.crypto.hashing import sha256_hash, sha256_hash_file
from app.crypto.kdf import hkdf_derive_key, pbkdf2_derive_key, generate_salt
from app.core.session import (
    STSSession,
    generate_ephemeral_keypair,
    serialize_ec_public_key,
    deserialize_ec_public_key,
    compute_shared_secret,
)




class TestRSAKeys:

    def test_generate_keypair(self):
        """Key generation produces a private and public key."""
        priv, pub = generate_rsa_keypair()
        assert priv is not None
        assert pub is not None

    def test_serialize_deserialize_round_trip(self):
        """Public key survives PEM serialization round-trip."""
        priv, pub = generate_rsa_keypair()
        pem = serialize_public_key(pub)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        restored = deserialize_public_key(pem)
        # Verify the restored key serializes to the same PEM
        assert serialize_public_key(restored) == pem

    def test_deserialize_accepts_string(self):
        """deserialize_public_key also accepts str input."""
        _, pub = generate_rsa_keypair()
        pem_str = serialize_public_key(pub).decode("utf-8")
        restored = deserialize_public_key(pem_str)
        assert serialize_public_key(restored) == serialize_public_key(pub)

    def test_save_load_private_key_no_password(self):
        """Private key can be saved and loaded without encryption."""
        priv, pub = generate_rsa_keypair()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_private_key(priv, path)
            loaded = load_private_key(path)
            # Verify the loaded key produces the same public key
            assert serialize_public_key(loaded.public_key()) == serialize_public_key(pub)
        finally:
            os.unlink(path)

    def test_save_load_private_key_with_password(self):
        """Private key can be encrypted with a password."""
        priv, pub = generate_rsa_keypair()
        password = b"test-password-123"
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_private_key(priv, path, password=password)
            loaded = load_private_key(path, password=password)
            assert serialize_public_key(loaded.public_key()) == serialize_public_key(pub)
        finally:
            os.unlink(path)

    def test_load_private_key_wrong_password_fails(self):
        """Loading an encrypted key with the wrong password raises."""
        priv, _ = generate_rsa_keypair()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            save_private_key(priv, path, password=b"correct")
            with pytest.raises(Exception):
                load_private_key(path, password=b"wrong")
        finally:
            os.unlink(path)

    def test_fingerprint_is_consistent(self):
        """Same key always produces the same fingerprint."""
        _, pub = generate_rsa_keypair()
        fp1 = get_fingerprint(pub)
        fp2 = get_fingerprint(pub)
        assert fp1 == fp2
        # Fingerprint should be colon-separated hex
        assert ":" in fp1
        assert len(fp1) == 95  # 32 bytes * 2 hex chars + 31 colons

    def test_different_keys_different_fingerprints(self):
        """Different keys produce different fingerprints."""
        _, pub1 = generate_rsa_keypair()
        _, pub2 = generate_rsa_keypair()
        assert get_fingerprint(pub1) != get_fingerprint(pub2)




class TestSigning:

    def test_sign_and_verify(self):
        """A valid signature verifies correctly."""
        priv, pub = generate_rsa_keypair()
        data = b"hello world"
        sig = sign_data(priv, data)
        assert verify_signature(pub, data, sig) is True

    def test_wrong_key_rejects(self):
        """A signature from a different key is rejected."""
        priv1, pub1 = generate_rsa_keypair()
        priv2, pub2 = generate_rsa_keypair()
        data = b"test data"
        sig = sign_data(priv1, data)
        # Verifying with pub2 (wrong key) should fail
        assert verify_signature(pub2, data, sig) is False

    def test_tampered_data_rejects(self):
        """Modified data fails verification."""
        priv, pub = generate_rsa_keypair()
        data = b"original data"
        sig = sign_data(priv, data)
        assert verify_signature(pub, b"modified data", sig) is False

    def test_tampered_signature_rejects(self):
        """Modified signature fails verification."""
        priv, pub = generate_rsa_keypair()
        data = b"test"
        sig = sign_data(priv, data)
        tampered_sig = bytearray(sig)
        tampered_sig[0] ^= 0xFF  # Flip bits
        assert verify_signature(pub, data, bytes(tampered_sig)) is False

    def test_empty_data(self):
        """Signing and verifying empty data works."""
        priv, pub = generate_rsa_keypair()
        sig = sign_data(priv, b"")
        assert verify_signature(pub, b"", sig) is True




class TestHashing:

    def test_known_hash(self):
        """SHA-256 of empty string matches known value."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hash(b"") == expected

    def test_hash_deterministic(self):
        """Same input always produces same hash."""
        data = b"hello"
        assert sha256_hash(data) == sha256_hash(data)

    def test_different_data_different_hash(self):
        assert sha256_hash(b"a") != sha256_hash(b"b")

    def test_hash_file(self):
        """File hashing matches in-memory hashing."""
        data = b"file contents for testing"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        try:
            assert sha256_hash_file(path) == sha256_hash(data)
        finally:
            os.unlink(path)



class TestKDF:

    def test_hkdf_deterministic(self):
        """Same inputs produce the same derived key."""
        secret = b"shared-secret-bytes"
        salt = b"fixed-salt"
        key1 = hkdf_derive_key(secret, salt=salt)
        key2 = hkdf_derive_key(secret, salt=salt)
        assert key1 == key2

    def test_hkdf_different_secrets(self):
        """Different secrets produce different keys."""
        salt = b"same-salt"
        key1 = hkdf_derive_key(b"secret-a", salt=salt)
        key2 = hkdf_derive_key(b"secret-b", salt=salt)
        assert key1 != key2

    def test_hkdf_key_length(self):
        """HKDF produces key of the requested length."""
        key = hkdf_derive_key(b"secret", length=16)
        assert len(key) == 16
        key = hkdf_derive_key(b"secret", length=32)
        assert len(key) == 32

    def test_pbkdf2_deterministic(self):
        """Same password + salt produce the same key."""
        salt = b"test-salt-16byte"
        key1 = pbkdf2_derive_key("password", salt, iterations=1000)
        key2 = pbkdf2_derive_key("password", salt, iterations=1000)
        assert key1 == key2

    def test_pbkdf2_different_passwords(self):
        """Different passwords produce different keys."""
        salt = b"same-salt-16byte"
        key1 = pbkdf2_derive_key("pass1", salt, iterations=1000)
        key2 = pbkdf2_derive_key("pass2", salt, iterations=1000)
        assert key1 != key2

    def test_pbkdf2_different_salts(self):
        """Different salts produce different keys."""
        key1 = pbkdf2_derive_key("same-pass", b"salt-a-16bytes!!", iterations=1000)
        key2 = pbkdf2_derive_key("same-pass", b"salt-b-16bytes!!", iterations=1000)
        assert key1 != key2

    def test_generate_salt_length(self):
        """Salt generator produces the right length."""
        assert len(generate_salt(16)) == 16
        assert len(generate_salt(32)) == 32

    def test_generate_salt_random(self):
        """Two generated salts should not be equal."""
        assert generate_salt() != generate_salt()




class TestECDH:

    def test_generate_ephemeral_keypair(self):
        """ECDH key generation produces a key pair."""
        priv, pub = generate_ephemeral_keypair()
        assert priv is not None
        assert pub is not None

    def test_ec_key_serialization_round_trip(self):
        """EC public key survives serialization round-trip."""
        _, pub = generate_ephemeral_keypair()
        serialized = serialize_ec_public_key(pub)
        restored = deserialize_ec_public_key(serialized)
        assert serialize_ec_public_key(restored) == serialized

    def test_ecdh_shared_secret_matches(self):
        """Both sides of ECDH compute the same shared secret."""
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        secret_a = compute_shared_secret(priv_a, pub_b)
        secret_b = compute_shared_secret(priv_b, pub_a)
        assert secret_a == secret_b

    def test_ecdh_different_pairs_different_secrets(self):
        """Different key pairs produce different shared secrets."""
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        priv_c, pub_c = generate_ephemeral_keypair()
        secret_ab = compute_shared_secret(priv_a, pub_b)
        secret_ac = compute_shared_secret(priv_a, pub_c)
        assert secret_ab != secret_ac




class TestSTSHandshake:
    """
    Tests the complete STS protocol:
    Alice (initiator) and Bob (responder) should end up with
    the same session key after the 3-message exchange.
    """

    def _make_keypairs(self):
        """Generate RSA key pairs for Alice and Bob."""
        alice_priv, alice_pub = generate_rsa_keypair()
        bob_priv, bob_pub = generate_rsa_keypair()
        return alice_priv, alice_pub, bob_priv, bob_pub

    def test_full_handshake_produces_matching_keys(self):
        """Both peers derive the same session key."""
        alice_priv, alice_pub, bob_priv, bob_pub = self._make_keypairs()

        # Alice creates session and initiates
        alice_session = STSSession(alice_priv, alice_pub)
        init_payload = alice_session.create_init()

        # Bob receives init and creates response
        bob_session = STSSession(bob_priv, bob_pub)
        response_payload = bob_session.handle_init(init_payload)

        # Alice receives response and creates confirm
        confirm_payload = alice_session.handle_response(response_payload)

        # Bob receives confirm
        bob_session.handle_confirm(confirm_payload)

        # Both sessions should be complete with matching keys
        assert alice_session.complete is True
        assert bob_session.complete is True
        assert alice_session.session_key is not None
        assert alice_session.session_key == bob_session.session_key

    def test_each_handshake_produces_unique_keys(self):
        """Two separate handshakes produce different session keys."""
        alice_priv, alice_pub, bob_priv, bob_pub = self._make_keypairs()

        # First handshake
        s1_alice = STSSession(alice_priv, alice_pub)
        s1_bob = STSSession(bob_priv, bob_pub)
        s1_bob_resp = s1_bob.handle_init(s1_alice.create_init())
        s1_alice.handle_response(s1_bob_resp)

        # Second handshake (same long-term keys, fresh ephemeral keys)
        s2_alice = STSSession(alice_priv, alice_pub)
        s2_bob = STSSession(bob_priv, bob_pub)
        s2_bob_resp = s2_bob.handle_init(s2_alice.create_init())
        s2_alice.handle_response(s2_bob_resp)

        assert s1_alice.session_key != s2_alice.session_key

    def test_tampered_responder_signature_rejected(self):
        """If Bob's signature is corrupted, Alice rejects the handshake."""
        alice_priv, alice_pub, bob_priv, bob_pub = self._make_keypairs()

        alice_session = STSSession(alice_priv, alice_pub)
        init_payload = alice_session.create_init()

        bob_session = STSSession(bob_priv, bob_pub)
        response_payload = bob_session.handle_init(init_payload)

        # Tamper with Bob's signature
        tampered_sig = bytearray(response_payload["signature"])
        tampered_sig[0] ^= 0xFF
        response_payload["signature"] = bytes(tampered_sig)

        with pytest.raises(ValueError, match="responder signature invalid"):
            alice_session.handle_response(response_payload)

    def test_tampered_initiator_signature_rejected(self):
        """If Alice's confirm signature is corrupted, Bob rejects."""
        alice_priv, alice_pub, bob_priv, bob_pub = self._make_keypairs()

        alice_session = STSSession(alice_priv, alice_pub)
        init_payload = alice_session.create_init()

        bob_session = STSSession(bob_priv, bob_pub)
        response_payload = bob_session.handle_init(init_payload)

        confirm_payload = alice_session.handle_response(response_payload)

        # Tamper with Alice's signature
        tampered_sig = bytearray(confirm_payload["signature"])
        tampered_sig[0] ^= 0xFF
        confirm_payload["signature"] = bytes(tampered_sig)

        with pytest.raises(ValueError, match="initiator signature invalid"):
            bob_session.handle_confirm(confirm_payload)

    def test_wrong_long_term_key_rejected(self):
        """Using a different RSA key in the response is rejected."""
        alice_priv, alice_pub, bob_priv, bob_pub = self._make_keypairs()
        _, imposter_pub = generate_rsa_keypair()

        alice_session = STSSession(alice_priv, alice_pub)
        init_payload = alice_session.create_init()

        # Bob uses his real key to sign, but an imposter's key is provided
        bob_session = STSSession(bob_priv, bob_pub)
        response_payload = bob_session.handle_init(init_payload)

        # Replace Bob's long-term key with the imposter's
        response_payload["long_term_public_key"] = serialize_public_key(imposter_pub)

        with pytest.raises(ValueError, match="responder signature invalid"):
            alice_session.handle_response(response_payload)

    def test_destroy_clears_session_key(self):
        """destroy() wipes the session key from memory."""
        alice_priv, alice_pub, bob_priv, bob_pub = self._make_keypairs()

        alice_session = STSSession(alice_priv, alice_pub)
        bob_session = STSSession(bob_priv, bob_pub)
        bob_resp = bob_session.handle_init(alice_session.create_init())
        alice_session.handle_response(bob_resp)

        assert alice_session.session_key is not None
        alice_session.destroy()
        assert alice_session.session_key is None
        assert alice_session.complete is False
