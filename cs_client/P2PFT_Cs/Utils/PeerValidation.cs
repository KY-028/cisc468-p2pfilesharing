using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using P2PFT_Cs.DataObj;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs
{
    /// <summary>
    /// Validates peer identities, manages public key storage, and handles
    /// the STS key-exchange handshake matching the Python client's protocol.
    ///
    /// STS handshake (3-message exchange on a single TCP socket):
    ///   1. INIT:     initiator sends ephemeral ECDH P-256 public key
    ///   2. RESPONSE: responder sends ephemeral key + long-term RSA pub + RSA-PSS signature
    ///   3. CONFIRM:  initiator sends long-term RSA pub + RSA-PSS signature
    ///
    /// Session key: ECDH shared secret -> HKDF-SHA256 (info="p2p-session-key")
    /// Signatures: RSA-PSS (SHA-256, MGF1-SHA256, MAX_LENGTH salt)
    /// Fingerprint: SHA-256(DER public key) -> colon-separated hex
    /// </summary>
    internal class PeerValidation
    {
        // ── Persistence path ────────────────────────────────────
        private static readonly string StoreDir =
            Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData), "P2PFT");

        private static readonly string StorePath =
            Path.Combine(StoreDir, "trusted_peers.json");

        // ── Wire protocol constants ─────────────────────────────
        private const int HeaderSize = 4;
        private const int MaxMessageSize = 64 * 1024 * 1024;

        // ── EC curve ────────────────────────────────────────────
        private static readonly X9ECParameters EcCurveParams =
            ECNamedCurveTable.GetByName("secp256r1");
        private static readonly ECDomainParameters EcDomain =
            new ECDomainParameters(
                EcCurveParams.Curve, EcCurveParams.G,
                EcCurveParams.N, EcCurveParams.H,
                EcCurveParams.GetSeed());

        private static readonly SecureRandom SecureRng = new SecureRandom();

        // ── Identity ────────────────────────────────────────────
        private readonly string _peerId;
        private readonly AccountManager _account;
        private readonly FileTransfer _fileTransfer;

        // ── In-memory peer records ──────────────────────────────
        private readonly ConcurrentDictionary<string, PeerRecord> _peers =
            new ConcurrentDictionary<string, PeerRecord>();

        // ── Mutual verification tracking ────────────────────────
        private readonly ConcurrentDictionary<string, bool> _verifyConfirmedByMe =
            new ConcurrentDictionary<string, bool>();
        private readonly ConcurrentDictionary<string, bool> _verifyConfirmedByPeer =
            new ConcurrentDictionary<string, bool>();

        /// <summary>
        /// Raised when a peer becomes fully verified (mutual confirmation).
        /// </summary>
        public event Action<string> PeerVerified;

        /// <summary>
        /// Raised when a peer's key is revoked and replaced.
        /// </summary>
        public event Action<string> PeerKeyRotated;

        /// <summary>
        /// Raised after a handshake completes with an unverified peer.
        /// Parameters: peerId, verificationCode.
        /// </summary>
        public event Action<string, string> VerificationRequired;

        // ── Constructor ─────────────────────────────────────────

        public PeerValidation(string peerId, AccountManager account,
                              FileTransfer fileTransfer)
        {
            if (string.IsNullOrEmpty(peerId))
                throw new ArgumentException("PeerId is required.", nameof(peerId));

            _peerId = peerId;
            _account = account ?? throw new ArgumentNullException(nameof(account));
            _fileTransfer = fileTransfer ?? throw new ArgumentNullException(nameof(fileTransfer));

            Load();
        }

        // ================================================================
        //  Public API -- query & mutate peer trust
        // ================================================================

        public bool IsTrusted(string peerId)
        {
            PeerRecord rec;
            return _peers.TryGetValue(peerId, out rec) && rec.Trusted;
        }

        public string GetFingerprint(string peerId)
        {
            PeerRecord rec;
            if (_peers.TryGetValue(peerId, out rec))
                return rec.Fingerprint;
            return null;
        }

        public string GetPublicKeyPem(string peerId)
        {
            PeerRecord rec;
            if (_peers.TryGetValue(peerId, out rec))
                return rec.PublicKeyPem;
            return null;
        }

        public IReadOnlyList<PeerRecord> GetAllPeers()
        {
            return _peers.Values.ToList().AsReadOnly();
        }

        public bool RegisterPeerKey(string peerId, string publicKeyPem,
                                     string claimedFingerprint)
        {
            if (string.IsNullOrEmpty(peerId) ||
                string.IsNullOrEmpty(publicKeyPem))
                return false;

            string computedFingerprint = ComputeFingerprintFromPem(publicKeyPem);
            if (computedFingerprint == null)
                return false;

            if (!string.IsNullOrEmpty(claimedFingerprint) &&
                !string.Equals(computedFingerprint, claimedFingerprint,
                                StringComparison.OrdinalIgnoreCase))
                return false;

            _peers[peerId] = new PeerRecord
            {
                PeerId = peerId,
                PublicKeyPem = publicKeyPem,
                Fingerprint = computedFingerprint,
                Trusted = false,
                LastUpdatedUtc = DateTime.UtcNow.ToString("o"),
            };

            Save();
            return true;
        }

        public bool ConfirmTrust(string peerId)
        {
            PeerRecord rec;
            if (!_peers.TryGetValue(peerId, out rec)) return false;
            if (string.IsNullOrEmpty(rec.PublicKeyPem)) return false;

            rec.Trusted = true;
            rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
            Save();
            PeerVerified?.Invoke(peerId);
            return true;
        }

        public void RevokeTrust(string peerId)
        {
            PeerRecord rec;
            if (_peers.TryGetValue(peerId, out rec))
            {
                rec.Trusted = false;
                rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
                Save();
            }
        }

        public void RemovePeer(string peerId)
        {
            PeerRecord removed;
            if (_peers.TryRemove(peerId, out removed))
                Save();
        }

        // ================================================================
        //  Fingerprint verification
        // ================================================================

        public bool VerifyFingerprint(string peerId, string claimedFingerprint)
        {
            PeerRecord rec;
            if (!_peers.TryGetValue(peerId, out rec))
                return false;

            string computed = ComputeFingerprintFromPem(rec.PublicKeyPem);
            return computed != null &&
                   string.Equals(computed, claimedFingerprint,
                                  StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Generates a verification code from two fingerprints, matching
        /// the Python client's algorithm:
        ///   sorted fingerprints joined by newline -> SHA-256 -> first 24
        ///   hex chars -> parse as big integer -> 30 decimal digits ->
        ///   6 groups of 5 digits separated by spaces.
        /// </summary>
        public static string GenerateVerificationCode(string myFingerprint,
                                                       string theirFingerprint)
        {
            if (string.IsNullOrEmpty(myFingerprint) ||
                string.IsNullOrEmpty(theirFingerprint))
                return null;

            var sorted = new[] { myFingerprint, theirFingerprint };
            Array.Sort(sorted, StringComparer.Ordinal);
            string combined = sorted[0] + "\n" + sorted[1];

            var digest = new Sha256Digest();
            byte[] input = Encoding.UTF8.GetBytes(combined);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(hash, 0);

            // Take first 24 hex chars (12 bytes) -> parse as big integer
            var sb = new StringBuilder(24);
            for (int i = 0; i < 12; i++)
                sb.Append(hash[i].ToString("x2"));
            string hexStr = sb.ToString();

            var codeInt = new BigInteger(hexStr, 16);

            // Convert to decimal, zero-pad to 30 digits, take first 30
            string codeDigits = codeInt.ToString();
            if (codeDigits.Length < 30)
                codeDigits = codeDigits.PadLeft(30, '0');
            if (codeDigits.Length > 30)
                codeDigits = codeDigits.Substring(0, 30);

            // Format as 6 groups of 5 digits
            var groups = new string[6];
            for (int i = 0; i < 6; i++)
                groups[i] = codeDigits.Substring(i * 5, 5);
            return string.Join(" ", groups);
        }

        // ================================================================
        //  STS Key Exchange -- INITIATOR
        // ================================================================

        /// <summary>
        /// Perform a full STS handshake as the INITIATOR.
        /// Opens a TCP connection and runs the 3-message exchange:
        ///   1. -> KEY_EXCHANGE_INIT     (our ephemeral pub)
        ///   2. <- KEY_EXCHANGE_RESPONSE (peer's eph + long-term pub + signature)
        ///   3. -> KEY_EXCHANGE_CONFIRM  (our long-term pub + signature)
        /// </summary>
        public void InitiateHandshake(string peerId, string address, int port)
        {
            // Generate our ephemeral ECDH key pair
            AsymmetricCipherKeyPair ecKeyPair = GenerateEcdhKeyPair();
            var ourEcPrivate = (ECPrivateKeyParameters)ecKeyPair.Private;
            var ourEcPublic = (ECPublicKeyParameters)ecKeyPair.Public;
            byte[] ourEphBytes = SerializeEcPublicKey(ourEcPublic);

            using (var client = new TcpClient())
            {
                client.Connect(address, port);
                client.SendTimeout = 15000;
                client.ReceiveTimeout = 15000;
                NetworkStream stream = client.GetStream();

                // Step 1: Send KEY_EXCHANGE_INIT
                var initMsg = new KeyExchangeInitMessage(new KeyExchangeInitPayload
                {
                    PeerId = _peerId,
                    EphemeralPublicKey = Convert.ToBase64String(ourEphBytes),
                });
                WriteMessage(stream, initMsg);

                // Step 2: Receive KEY_EXCHANGE_RESPONSE
                string respJson = ReadMessage(stream);
                if (respJson == null)
                    throw new InvalidOperationException("Connection closed, no response");

                string respType = ExtractJsonString(respJson, "type");
                if (respType != MessageType.KeyExchangeResponse)
                    throw new InvalidOperationException(
                        "Expected KEY_EXCHANGE_RESPONSE, got " + respType);

                // Parse response payload fields
                string peerEphB64 = ExtractPayloadField(respJson, "ephemeral_public_key");
                string peerLongTermB64 = ExtractPayloadField(respJson, "long_term_public_key");
                string signatureB64 = ExtractPayloadField(respJson, "signature");

                byte[] peerEphBytes = Convert.FromBase64String(peerEphB64);
                // long_term_public_key is base64(PEM bytes)
                string peerLongTermPem = Encoding.UTF8.GetString(
                    Convert.FromBase64String(peerLongTermB64));
                byte[] signatureBytes = Convert.FromBase64String(signatureB64);

                // Deserialize peer's keys
                ECPublicKeyParameters peerEcPublic = DeserializeEcPublicKey(peerEphBytes);
                AsymmetricKeyParameter peerRsaPublic = ParsePublicKeyPem(peerLongTermPem);

                // Verify responder's signature: Sig(peer_eph || our_eph)
                byte[] signedData = ConcatBytes(peerEphBytes, ourEphBytes);
                if (!RsaPssVerify(peerRsaPublic, signedData, signatureBytes))
                    throw new InvalidOperationException(
                        "STS handshake failed: responder signature invalid");

                // Compute shared secret and derive session key
                byte[] sharedSecret = ComputeEcdhSharedSecret(ourEcPrivate, peerEcPublic);
                byte[] sessionKey = HkdfDeriveKey(sharedSecret);

                // Step 3: Send KEY_EXCHANGE_CONFIRM
                // Sign: Sig(our_eph || peer_eph)
                byte[] ourSignedData = ConcatBytes(ourEphBytes, peerEphBytes);
                byte[] ourSignature = RsaPssSign(
                    _account.RsaKeyPair.Private, ourSignedData);

                string ourPubKeyPem = _account.GetPublicKeyPem();
                var confirmMsg = new KeyExchangeConfirmMessage(new KeyExchangeConfirmPayload
                {
                    PeerId = _peerId,
                    LongTermPublicKey = Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(ourPubKeyPem)),
                    Signature = Convert.ToBase64String(ourSignature),
                });
                WriteMessage(stream, confirmMsg);

                // Store results
                _fileTransfer.SetSessionKey(peerId, sessionKey);
                string fp = ComputeFingerprintFromPem(peerLongTermPem);
                if (fp != null)
                    RegisterPeerKey(peerId, peerLongTermPem, fp);

                // Generate verification code if not already trusted
                RaiseVerificationIfNeeded(peerId);
            }
        }

        // ================================================================
        //  STS Key Exchange -- RESPONDER (same-socket)
        // ================================================================

        /// <summary>
        /// Handles an incoming KEY_EXCHANGE_INIT as the RESPONDER.
        /// Runs the remaining 2 messages on the SAME TCP connection:
        ///   1. (already received) KEY_EXCHANGE_INIT
        ///   2. -> KEY_EXCHANGE_RESPONSE (our eph + long-term pub + signature)
        ///   3. <- KEY_EXCHANGE_CONFIRM  (peer's long-term pub + signature)
        /// The caller must NOT close the TcpClient; this method handles cleanup.
        /// </summary>
        public void HandleKeyExchangeInit(KeyExchangeInitPayload payload,
                                           TcpClient client,
                                           NetworkStream stream,
                                           string senderAddress)
        {
            string remotePeerId = payload.PeerId;

            try
            {
                // Parse initiator's ephemeral key
                byte[] peerEphBytes = Convert.FromBase64String(payload.EphemeralPublicKey);
                ECPublicKeyParameters peerEcPublic = DeserializeEcPublicKey(peerEphBytes);

                // Generate our ephemeral ECDH key pair
                AsymmetricCipherKeyPair ecKeyPair = GenerateEcdhKeyPair();
                var ourEcPrivate = (ECPrivateKeyParameters)ecKeyPair.Private;
                var ourEcPublic = (ECPublicKeyParameters)ecKeyPair.Public;
                byte[] ourEphBytes = SerializeEcPublicKey(ourEcPublic);

                // Sign: Sig(our_eph || peer_eph)
                byte[] signedData = ConcatBytes(ourEphBytes, peerEphBytes);
                byte[] signature = RsaPssSign(_account.RsaKeyPair.Private, signedData);

                string ourPubKeyPem = _account.GetPublicKeyPem();

                // Step 2: Send KEY_EXCHANGE_RESPONSE
                var respMsg = new KeyExchangeResponseMessage(new KeyExchangeResponsePayload
                {
                    PeerId = _peerId,
                    EphemeralPublicKey = Convert.ToBase64String(ourEphBytes),
                    LongTermPublicKey = Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(ourPubKeyPem)),
                    Signature = Convert.ToBase64String(signature),
                });
                WriteMessage(stream, respMsg);

                // Step 3: Receive KEY_EXCHANGE_CONFIRM
                string confJson = ReadMessage(stream);
                if (confJson == null)
                    throw new InvalidOperationException("Connection closed, no confirm received");

                string confType = ExtractJsonString(confJson, "type");
                if (confType != MessageType.KeyExchangeConfirm)
                    throw new InvalidOperationException(
                        "Expected KEY_EXCHANGE_CONFIRM, got " + confType);

                string peerLongTermB64 = ExtractPayloadField(confJson, "long_term_public_key");
                string confSigB64 = ExtractPayloadField(confJson, "signature");

                string peerLongTermPem = Encoding.UTF8.GetString(
                    Convert.FromBase64String(peerLongTermB64));
                byte[] confSigBytes = Convert.FromBase64String(confSigB64);

                AsymmetricKeyParameter peerRsaPublic = ParsePublicKeyPem(peerLongTermPem);

                // Verify initiator's signature: Sig(peer_eph || our_eph)
                byte[] confSignedData = ConcatBytes(peerEphBytes, ourEphBytes);
                if (!RsaPssVerify(peerRsaPublic, confSignedData, confSigBytes))
                    throw new InvalidOperationException(
                        "STS handshake failed: initiator signature invalid");

                // Compute shared secret and derive session key
                byte[] sharedSecret = ComputeEcdhSharedSecret(ourEcPrivate, peerEcPublic);
                byte[] sessionKey = HkdfDeriveKey(sharedSecret);

                // Store results
                _fileTransfer.SetSessionKey(remotePeerId, sessionKey);
                string fp = ComputeFingerprintFromPem(peerLongTermPem);
                if (fp != null)
                    RegisterPeerKey(remotePeerId, peerLongTermPem, fp);

                // Generate verification code if not already trusted
                RaiseVerificationIfNeeded(remotePeerId);
            }
            catch (Exception)
            {
                // Handshake failed
            }
            finally
            {
                try { client.Close(); } catch { }
            }
        }

        // ================================================================
        //  Verification Confirm / Reject
        // ================================================================

        /// <summary>
        /// Called when the local user confirms the verification code.
        /// Sends VERIFY_CONFIRM to the peer and records local confirmation.
        /// </summary>
        public void ConfirmVerification(string peerId, string address, int port)
        {
            _verifyConfirmedByMe[peerId] = true;

            // Send VERIFY_CONFIRM to peer
            SendVerifyMessage(peerId, address, port, isConfirm: true);

            // Check if peer already confirmed
            bool peerConfirmed;
            if (_verifyConfirmedByPeer.TryGetValue(peerId, out peerConfirmed) && peerConfirmed)
            {
                CompleteMutualVerification(peerId);
            }
        }

        /// <summary>
        /// Called when the local user rejects the verification code.
        /// Sends VERIFY_REJECT to the peer.
        /// </summary>
        public void RejectVerification(string peerId, string address, int port)
        {
            SendVerifyMessage(peerId, address, port, isConfirm: false);
        }

        /// <summary>
        /// Handles an incoming VERIFY_CONFIRM from a peer.
        /// </summary>
        public void HandleVerifyConfirm(VerifyConfirmPayload payload)
        {
            string peerId = payload.PeerId;
            _verifyConfirmedByPeer[peerId] = true;

            bool meConfirmed;
            if (_verifyConfirmedByMe.TryGetValue(peerId, out meConfirmed) && meConfirmed)
            {
                CompleteMutualVerification(peerId);
            }
        }

        /// <summary>
        /// Handles an incoming VERIFY_REJECT from a peer.
        /// </summary>
        public void HandleVerifyReject(VerifyRejectPayload payload)
        {
            string peerId = payload.PeerId;
            bool removed;
            _verifyConfirmedByMe.TryRemove(peerId, out removed);
            _verifyConfirmedByPeer.TryRemove(peerId, out removed);
        }

        private void CompleteMutualVerification(string peerId)
        {
            bool removed;
            _verifyConfirmedByMe.TryRemove(peerId, out removed);
            _verifyConfirmedByPeer.TryRemove(peerId, out removed);
            ConfirmTrust(peerId);
        }

        // ================================================================
        //  Key Revocation
        // ================================================================

        public void HandleKeyRevocation(RevokeKeyPayload payload)
        {
            string remotePeerId = payload.PeerId;
            string newPubKeyPem = payload.NewPublicKey;
            string crossSigBase64 = payload.CrossSignature;

            if (string.IsNullOrEmpty(newPubKeyPem)) return;

            PeerRecord rec;
            if (!_peers.TryGetValue(remotePeerId, out rec)) return;

            // Verify cross-signature: the old key must have signed the new public key PEM
            if (!string.IsNullOrEmpty(crossSigBase64) && !string.IsNullOrEmpty(rec.PublicKeyPem))
            {
                try
                {
                    var oldPubKey = ParsePublicKeyPem(rec.PublicKeyPem);
                    byte[] newPubKeyBytes = System.Text.Encoding.UTF8.GetBytes(newPubKeyPem);
                    byte[] crossSigBytes = Convert.FromBase64String(crossSigBase64);

                    if (!RsaPssVerify(oldPubKey, newPubKeyBytes, crossSigBytes))
                    {
                        // SECURITY: cross-signature invalid — reject revocation
                        return;
                    }
                }
                catch
                {
                    return; // Malformed signature — reject
                }
            }
            else
            {
                // No cross-signature provided — reject for security
                return;
            }

            string newFingerprint = ComputeFingerprintFromPem(newPubKeyPem);
            if (newFingerprint == null) return;

            rec.PublicKeyPem = newPubKeyPem;
            rec.Fingerprint = newFingerprint;
            rec.Trusted = false;
            rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
            Save();
            PeerKeyRotated?.Invoke(remotePeerId);
        }

        /// <summary>
        /// Cross-signs data with the given private key (RSA-PSS SHA-256).
        /// Used for key rotation — sign the new public key PEM with the old private key.
        /// </summary>
        public string CrossSign(AsymmetricKeyParameter oldPrivateKey, byte[] data)
        {
            byte[] signature = RsaPssSign(oldPrivateKey, data);
            return Convert.ToBase64String(signature);
        }

        // ================================================================
        //  Persistence -- JSON file
        // ================================================================

        private void Save()
        {
            try
            {
                if (!Directory.Exists(StoreDir))
                    Directory.CreateDirectory(StoreDir);

                var snapshot = new PeerStoreFile
                {
                    Peers = _peers.Values.ToList(),
                };

                var serializer = new DataContractJsonSerializer(typeof(PeerStoreFile));
                using (var ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, snapshot);
                    File.WriteAllBytes(StorePath, ms.ToArray());
                }
            }
            catch { /* best effort */ }
        }

        private void Load()
        {
            if (!File.Exists(StorePath)) return;

            try
            {
                byte[] data = File.ReadAllBytes(StorePath);
                var serializer = new DataContractJsonSerializer(typeof(PeerStoreFile));
                using (var ms = new MemoryStream(data))
                {
                    var store = (PeerStoreFile)serializer.ReadObject(ms);
                    if (store?.Peers != null)
                    {
                        foreach (var rec in store.Peers)
                        {
                            _peers[rec.PeerId] = rec;
                        }
                    }
                }
            }
            catch { /* file corrupted -- start fresh */ }
        }

        // ================================================================
        //  ECDH P-256 helpers
        // ================================================================

        private static AsymmetricCipherKeyPair GenerateEcdhKeyPair()
        {
            var generator = new ECKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(EcDomain, SecureRng));
            return generator.GenerateKeyPair();
        }

        /// <summary>
        /// Serialize an EC public key to X9.62 uncompressed point (65 bytes for P-256).
        /// </summary>
        private static byte[] SerializeEcPublicKey(ECPublicKeyParameters pubKey)
        {
            return pubKey.Q.GetEncoded(false); // false = uncompressed
        }

        /// <summary>
        /// Deserialize X9.62 uncompressed point bytes to an EC public key.
        /// </summary>
        private static ECPublicKeyParameters DeserializeEcPublicKey(byte[] pointBytes)
        {
            ECPoint q = EcCurveParams.Curve.DecodePoint(pointBytes);
            return new ECPublicKeyParameters("ECDH", q, EcDomain);
        }

        /// <summary>
        /// Perform ECDH key agreement, returning the raw shared secret
        /// (x-coordinate, zero-padded to 32 bytes for P-256).
        /// </summary>
        private static byte[] ComputeEcdhSharedSecret(ECPrivateKeyParameters ourPrivate,
                                                       ECPublicKeyParameters theirPublic)
        {
            var agreement = new ECDHBasicAgreement();
            agreement.Init(ourPrivate);
            BigInteger sharedSecretInt = agreement.CalculateAgreement(theirPublic);

            // Convert to fixed 32 bytes (P-256 field size)
            byte[] raw = sharedSecretInt.ToByteArrayUnsigned();
            if (raw.Length == 32) return raw;
            byte[] padded = new byte[32];
            if (raw.Length < 32)
            {
                int offset = 32 - raw.Length;
                Array.Copy(raw, 0, padded, offset, raw.Length);
            }
            else
            {
                Array.Copy(raw, raw.Length - 32, padded, 0, 32);
            }
            return padded;
        }

        // ================================================================
        //  RSA-PSS signing / verification
        // ================================================================

        /// <summary>
        /// Compute the PSS MAX_LENGTH salt for an RSA key.
        /// For RSA-2048: (256 - 32 - 2) = 222 bytes.
        /// </summary>
        private static int GetPssMaxSaltLength(AsymmetricKeyParameter key)
        {
            int modulusBits;
            if (key is RsaKeyParameters rsaKey)
                modulusBits = rsaKey.Modulus.BitLength;
            else
                modulusBits = 2048;

            int emLen = (modulusBits + 7) / 8;
            return emLen - 32 - 2; // emLen - hLen - 2
        }

        private static byte[] RsaPssSign(AsymmetricKeyParameter privateKey, byte[] data)
        {
            int saltLen = GetPssMaxSaltLength(privateKey);
            var signer = new PssSigner(
                new RsaBlindedEngine(), new Sha256Digest(),
                new Sha256Digest(), saltLen);
            signer.Init(true, new ParametersWithRandom(privateKey, SecureRng));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        private static bool RsaPssVerify(AsymmetricKeyParameter publicKey,
                                          byte[] data, byte[] signature)
        {
            try
            {
                int saltLen = GetPssMaxSaltLength(publicKey);
                var verifier = new PssSigner(
                    new RsaBlindedEngine(), new Sha256Digest(),
                    new Sha256Digest(), saltLen);
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(data, 0, data.Length);
                return verifier.VerifySignature(signature);
            }
            catch
            {
                return false;
            }
        }

        // ================================================================
        //  HKDF-SHA256 key derivation
        // ================================================================

        /// <summary>
        /// Derive a 32-byte session key from an ECDH shared secret using
        /// HKDF-SHA256 with info="p2p-session-key" and no salt (RFC 5869 zero salt).
        /// </summary>
        private static byte[] HkdfDeriveKey(byte[] sharedSecret)
        {
            byte[] info = Encoding.UTF8.GetBytes("p2p-session-key");
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            // null salt -> HKDF uses zero-filled salt of hash length per RFC 5869
            hkdf.Init(new HkdfParameters(sharedSecret, null, info));
            byte[] output = new byte[32];
            hkdf.GenerateBytes(output, 0, 32);
            return output;
        }

        // ================================================================
        //  Fingerprint helpers
        // ================================================================

        /// <summary>
        /// Computes SHA-256(DER SubjectPublicKeyInfo) from a PEM string.
        /// Returns colon-separated lowercase hex matching the Python client format.
        /// </summary>
        private static string ComputeFingerprintFromPem(string publicKeyPem)
        {
            try
            {
                AsymmetricKeyParameter pubKey = ParsePublicKeyPem(publicKeyPem);
                var info = SubjectPublicKeyInfoFactory
                    .CreateSubjectPublicKeyInfo(pubKey);
                byte[] der = info.GetDerEncoded();
                return AccountManager.ComputeFingerprintFromDer(der);
            }
            catch
            {
                return null;
            }
        }

        private static AsymmetricKeyParameter ParsePublicKeyPem(string pem)
        {
            using (var sr = new StringReader(pem))
            {
                var reader = new PemReader(sr);
                object obj = reader.ReadObject();
                if (obj is AsymmetricKeyParameter akp)
                    return akp;
                if (obj is AsymmetricCipherKeyPair pair)
                    return pair.Public;
                throw new InvalidOperationException("PEM does not contain a valid public key.");
            }
        }

        // ================================================================
        //  Wire protocol helpers (length-prefixed JSON)
        // ================================================================

        private static void WriteMessage<TPayload>(NetworkStream stream,
                                                    jsonBody<TPayload> message)
            where TPayload : BasePayload
        {
            var serializer = new DataContractJsonSerializer(message.GetType());
            byte[] payload;
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, message);
                payload = ms.ToArray();
            }

            byte[] header = BitConverter.GetBytes(payload.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(header);

            stream.Write(header, 0, header.Length);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        }

        private static string ReadMessage(NetworkStream stream)
        {
            byte[] headerBuf = ReadExactly(stream, HeaderSize);
            if (headerBuf == null) return null;

            int length = FromBigEndian(headerBuf, 0);
            if (length <= 0 || length > MaxMessageSize) return null;

            byte[] payloadBuf = ReadExactly(stream, length);
            if (payloadBuf == null) return null;

            return Encoding.UTF8.GetString(payloadBuf);
        }

        private static byte[] ReadExactly(NetworkStream stream, int count)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(buffer, offset, count - offset);
                if (read == 0) return null;
                offset += read;
            }
            return buffer;
        }

        private static int FromBigEndian(byte[] data, int offset)
        {
            byte[] buf = new byte[4];
            Buffer.BlockCopy(data, offset, buf, 0, 4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(buf);
            return BitConverter.ToInt32(buf, 0);
        }

        private void SendVerifyMessage(string peerId, string address, int port,
                                        bool isConfirm)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    client.Connect(address, port);
                    client.SendTimeout = 15000;
                    NetworkStream stream = client.GetStream();

                    if (isConfirm)
                    {
                        var msg = new VerifyConfirmMessage(new VerifyConfirmPayload
                        {
                            PeerId = _peerId,
                        });
                        WriteMessage(stream, msg);
                    }
                    else
                    {
                        var msg = new VerifyRejectMessage(new VerifyRejectPayload
                        {
                            PeerId = _peerId,
                        });
                        WriteMessage(stream, msg);
                    }
                }
            }
            catch { /* best effort */ }
        }

        // ================================================================
        //  JSON field extraction (lightweight, no full parse)
        // ================================================================

        private static string ExtractJsonString(string json, string key)
        {
            string marker = "\"" + key + "\":\"";
            int idx = json.IndexOf(marker, StringComparison.Ordinal);
            if (idx < 0) return null;
            int start = idx + marker.Length;
            int end = json.IndexOf('"', start);
            if (end < 0) return null;
            return json.Substring(start, end - start);
        }

        /// <summary>
        /// Extracts a payload field value from a JSON string.
        /// Searches within the "payload" section for the field.
        /// </summary>
        private static string ExtractPayloadField(string json, string key)
        {
            int payloadIdx = json.IndexOf("\"payload\"", StringComparison.Ordinal);
            if (payloadIdx < 0) return ExtractJsonString(json, key);

            string payloadSection = json.Substring(payloadIdx);
            return ExtractJsonString(payloadSection, key);
        }

        // ================================================================
        //  General helpers
        // ================================================================

        private static byte[] ConcatBytes(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }

        private void RaiseVerificationIfNeeded(string peerId)
        {
            PeerRecord rec;
            if (!_peers.TryGetValue(peerId, out rec)) return;
            if (rec.Trusted) return;

            string myFp = _account.GetFingerprint();
            string theirFp = rec.Fingerprint;
            if (string.IsNullOrEmpty(myFp) || string.IsNullOrEmpty(theirFp))
                return;

            string code = GenerateVerificationCode(myFp, theirFp);
            if (code != null)
                VerificationRequired?.Invoke(peerId, code);
        }

        // ================================================================
        //  Data types
        // ================================================================

        [DataContract]
        internal class PeerRecord
        {
            [DataMember(Name = "peer_id")]
            public string PeerId { get; set; }

            [DataMember(Name = "public_key_pem")]
            public string PublicKeyPem { get; set; }

            [DataMember(Name = "fingerprint")]
            public string Fingerprint { get; set; }

            [DataMember(Name = "trusted")]
            public bool Trusted { get; set; }

            [DataMember(Name = "last_updated_utc")]
            public string LastUpdatedUtc { get; set; }
        }

        [DataContract]
        private class PeerStoreFile
        {
            [DataMember(Name = "peers")]
            public List<PeerRecord> Peers { get; set; }
        }
    }
}
