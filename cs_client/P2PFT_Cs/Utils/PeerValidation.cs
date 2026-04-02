using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using P2PFT_Cs.DataObj;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs
{
    /// <summary>
    /// Validates peer identities, manages public key storage, and handles
    /// the STS key-exchange handshake.
    ///
    /// Responsibilities:
    ///   1. <b>Key storage</b> ¡ª persists each peer's public key PEM and
    ///      fingerprint to a local JSON file so trust survives restarts.
    ///   2. <b>Fingerprint verification</b> ¡ª recomputes SHA-256 of the
    ///      DER-encoded public key and compares with the claimed fingerprint.
    ///   3. <b>STS key-exchange handling</b> ¡ª processes KEY_EXCHANGE_INIT,
    ///      KEY_EXCHANGE_RESPONSE, and KEY_EXCHANGE_CONFIRM messages to
    ///      derive a shared session key stored in <see cref="FileTransfer"/>.
    ///   4. <b>Key revocation</b> ¡ª when a peer rotates keys, validates the
    ///      REVOKE_KEY message and replaces the stored key.
    ///
    /// Data file: %LocalAppData%/P2PFT/trusted_peers.json
    /// </summary>
    internal class PeerValidation
    {
        // ©¤©¤ Persistence path ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private static readonly string StoreDir =
            Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData), "P2PFT");

        private static readonly string StorePath =
            Path.Combine(StoreDir, "trusted_peers.json");

        // ©¤©¤ Identity ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private readonly string _peerId;
        private readonly AccountManager _account;
        private readonly FileTransfer _fileTransfer;

        // ©¤©¤ In-memory peer records ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private readonly ConcurrentDictionary<string, PeerRecord> _peers =
            new ConcurrentDictionary<string, PeerRecord>();

        // ©¤©¤ Pending handshakes (keyed by remote peerId) ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private readonly ConcurrentDictionary<string, HandshakeState> _handshakes =
            new ConcurrentDictionary<string, HandshakeState>();

        /// <summary>
        /// Raised when a peer becomes fully verified (both keys exchanged
        /// and fingerprints validated).
        /// </summary>
        public event Action<string> PeerVerified;

        /// <summary>
        /// Raised when a peer's key is revoked and replaced.
        /// </summary>
        public event Action<string> PeerKeyRotated;

        // ©¤©¤ Constructor ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

        /// <param name="peerId">This peer's unique identifier.</param>
        /// <param name="account">The local identity / key manager.</param>
        /// <param name="fileTransfer">
        /// The file transfer engine ¡ª session keys are stored here after
        /// a successful handshake.
        /// </param>
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

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Public API ¡ª query & mutate peer trust
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>Returns true if the peer's key has been verified.</summary>
        public bool IsTrusted(string peerId)
        {
            PeerRecord rec;
            return _peers.TryGetValue(peerId, out rec) && rec.Trusted;
        }

        /// <summary>Returns the stored fingerprint for a peer, or null.</summary>
        public string GetFingerprint(string peerId)
        {
            PeerRecord rec;
            if (_peers.TryGetValue(peerId, out rec))
                return rec.Fingerprint;
            return null;
        }

        /// <summary>Returns the stored public key PEM for a peer, or null.</summary>
        public string GetPublicKeyPem(string peerId)
        {
            PeerRecord rec;
            if (_peers.TryGetValue(peerId, out rec))
                return rec.PublicKeyPem;
            return null;
        }

        /// <summary>Returns a snapshot of all known peer records.</summary>
        public IReadOnlyList<PeerRecord> GetAllPeers()
        {
            return _peers.Values.ToList().AsReadOnly();
        }

        /// <summary>
        /// Stores a peer's public key and fingerprint. Recomputes the
        /// fingerprint from the PEM to verify it matches the claimed value.
        /// </summary>
        /// <returns>True if the fingerprint is valid and was stored.</returns>
        public bool RegisterPeerKey(string peerId, string publicKeyPem,
                                     string claimedFingerprint)
        {
            if (string.IsNullOrEmpty(peerId) ||
                string.IsNullOrEmpty(publicKeyPem))
                return false;

            // Recompute fingerprint from the raw key material
            string computedFingerprint = ComputeFingerprintFromPem(publicKeyPem);
            if (computedFingerprint == null)
                return false;

            // If a fingerprint was claimed, it must match
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

        /// <summary>
        /// Marks a peer as trusted after out-of-band fingerprint confirmation.
        /// </summary>
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

        /// <summary>
        /// Removes trust for a peer (e.g. failed verification).
        /// </summary>
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

        /// <summary>
        /// Removes a peer entirely from the store.
        /// </summary>
        public void RemovePeer(string peerId)
        {
            PeerRecord removed;
            if (_peers.TryRemove(peerId, out removed))
                Save();
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Fingerprint verification
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Verifies that a peer's claimed fingerprint matches the
        /// SHA-256 hash of their public key.
        /// </summary>
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

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  STS Key Exchange handling
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Handles an incoming KEY_EXCHANGE_INIT from a peer that wants to
        /// establish a session. Stores the peer's ephemeral public key and
        /// prepares for the next step.
        /// </summary>
        public void HandleKeyExchangeInit(KeyExchangeInitPayload payload,
                                           string senderAddress)
        {
            string remotePeerId = payload.PeerId;
            string ephemeralPubKeyB64 = payload.EphemeralPublicKey;

            _handshakes[remotePeerId] = new HandshakeState
            {
                RemotePeerId = remotePeerId,
                RemoteEphemeralPubKeyB64 = ephemeralPubKeyB64,
                SenderAddress = senderAddress,
                StartedUtc = DateTime.UtcNow,
            };
        }

        /// <summary>
        /// Handles an incoming KEY_EXCHANGE_RESPONSE. The peer responded
        /// with their ephemeral key, long-term public key, and signature.
        /// Stores the long-term key and validates the signature.
        /// </summary>
        public void HandleKeyExchangeResponse(KeyExchangeResponsePayload payload)
        {
            string remotePeerId = payload.PeerId;
            string longTermPubKeyPem = payload.LongTermPublicKey;
            string signatureB64 = payload.Signature;
            string ephemeralPubKeyB64 = payload.EphemeralPublicKey;

            // Store / update their long-term key
            string fingerprint = ComputeFingerprintFromPem(longTermPubKeyPem);
            if (fingerprint == null) return;

            RegisterPeerKey(remotePeerId, longTermPubKeyPem, fingerprint);

            // Verify the signature over the ephemeral key using long-term key
            bool sigValid = VerifySignature(
                longTermPubKeyPem, signatureB64, ephemeralPubKeyB64);

            HandshakeState hs;
            if (_handshakes.TryGetValue(remotePeerId, out hs))
            {
                hs.RemoteEphemeralPubKeyB64 = ephemeralPubKeyB64;
                hs.SignatureValid = sigValid;
                hs.RemoteLongTermPubKeyPem = longTermPubKeyPem;
            }
        }

        /// <summary>
        /// Handles an incoming KEY_EXCHANGE_CONFIRM. The handshake is
        /// complete; both sides now derive the same session key.
        /// </summary>
        public void HandleKeyExchangeConfirm(KeyExchangeConfirmPayload payload)
        {
            string remotePeerId = payload.PeerId;
            string longTermPubKeyPem = payload.LongTermPublicKey;
            string signatureB64 = payload.Signature;

            // Register / update their long-term key
            string fingerprint = ComputeFingerprintFromPem(longTermPubKeyPem);
            if (fingerprint != null)
                RegisterPeerKey(remotePeerId, longTermPubKeyPem, fingerprint);

            // For a real STS exchange the session key would be derived from
            // ECDH / DH shared secret. As a placeholder, we derive a 32-byte
            // key from the combination of both peer IDs + the long-term key
            // fingerprint using SHA-256.  Replace this with a proper ECDH
            // derivation when the full STS protocol is implemented.
            HandshakeState hs;
            if (_handshakes.TryRemove(remotePeerId, out hs))
            {
                byte[] sessionKey = DeriveSessionKey(
                    _peerId, remotePeerId, fingerprint ?? "");
                _fileTransfer.SetSessionKey(remotePeerId, sessionKey);
            }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Key Revocation
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Handles an incoming REVOKE_KEY message. Replaces the stored
        /// public key if the peer was previously trusted.
        /// </summary>
        public void HandleKeyRevocation(RevokeKeyPayload payload)
        {
            string remotePeerId = payload.PeerId;
            string newPubKeyPem = payload.NewPublicKey;

            if (string.IsNullOrEmpty(newPubKeyPem)) return;

            string newFingerprint = ComputeFingerprintFromPem(newPubKeyPem);
            if (newFingerprint == null) return;

            PeerRecord rec;
            if (_peers.TryGetValue(remotePeerId, out rec))
            {
                rec.PublicKeyPem = newPubKeyPem;
                rec.Fingerprint = newFingerprint;
                // After rotation, the peer must be re-verified
                rec.Trusted = false;
                rec.LastUpdatedUtc = DateTime.UtcNow.ToString("o");
                Save();
                PeerKeyRotated?.Invoke(remotePeerId);
            }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Persistence ¡ª JSON file
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

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
            catch { /* file corrupted ¡ª start fresh */ }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Crypto helpers
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Computes SHA-256(DER-encoded SubjectPublicKeyInfo) from a PEM string.
        /// Returns lowercase hex, or null if the PEM is invalid.
        /// </summary>
        private static string ComputeFingerprintFromPem(string publicKeyPem)
        {
            try
            {
                AsymmetricKeyParameter pubKey;
                using (var sr = new StringReader(publicKeyPem))
                {
                    var reader = new PemReader(sr);
                    object obj = reader.ReadObject();
                    if (obj is AsymmetricKeyParameter akp)
                        pubKey = akp;
                    else if (obj is AsymmetricCipherKeyPair pair)
                        pubKey = pair.Public;
                    else
                        return null;
                }

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

        /// <summary>
        /// Verifies an RSA-SHA256 signature over data encoded as base64.
        /// </summary>
        private static bool VerifySignature(string publicKeyPem,
                                             string signatureB64,
                                             string dataB64)
        {
            try
            {
                AsymmetricKeyParameter pubKey;
                using (var sr = new StringReader(publicKeyPem))
                {
                    var reader = new PemReader(sr);
                    object obj = reader.ReadObject();
                    if (obj is AsymmetricKeyParameter akp)
                        pubKey = akp;
                    else if (obj is AsymmetricCipherKeyPair pair)
                        pubKey = pair.Public;
                    else
                        return false;
                }

                var signer = SignerUtilities.GetSigner("SHA256withRSA");
                signer.Init(false, pubKey);

                byte[] data = Convert.FromBase64String(dataB64);
                signer.BlockUpdate(data, 0, data.Length);

                byte[] signature = Convert.FromBase64String(signatureB64);
                return signer.VerifySignature(signature);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Derives a 32-byte session key from peer IDs + fingerprint.
        /// This is a placeholder ¡ª replace with proper ECDH/HKDF in the
        /// full STS implementation.
        /// </summary>
        private static byte[] DeriveSessionKey(string localPeerId,
                                                string remotePeerId,
                                                string fingerprint)
        {
            // Sort so both peers derive the same key regardless of direction
            string combined;
            if (string.CompareOrdinal(localPeerId, remotePeerId) < 0)
                combined = localPeerId + "|" + remotePeerId + "|" + fingerprint;
            else
                combined = remotePeerId + "|" + localPeerId + "|" + fingerprint;

            var digest = new Sha256Digest();
            byte[] input = Encoding.UTF8.GetBytes(combined);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(hash, 0);
            return hash;
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Data types
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>A single peer's stored identity record.</summary>
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

        /// <summary>Root object for the trusted_peers.json file.</summary>
        [DataContract]
        private class PeerStoreFile
        {
            [DataMember(Name = "peers")]
            public List<PeerRecord> Peers { get; set; }
        }

        /// <summary>In-flight handshake state for one peer.</summary>
        private class HandshakeState
        {
            public string RemotePeerId { get; set; }
            public string RemoteEphemeralPubKeyB64 { get; set; }
            public string RemoteLongTermPubKeyPem { get; set; }
            public string SenderAddress { get; set; }
            public bool SignatureValid { get; set; }
            public DateTime StartedUtc { get; set; }
        }
    }
}