using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Json;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using P2PFT_Cs.DataObj;

namespace P2PFT_Cs.Utils
{
    /// <summary>
    /// Manages user identity creation, persistence, and loading.
    /// All cryptographic operations use Org.BouncyCastle for consistency.
    ///
    /// On first run:
    ///   1. Generates an RSA-2048 key pair (long-term identity).
    ///   2. Computes the fingerprint = SHA-256(DER-encoded public key) as hex.
    ///   3. Hashes the password with PBKDF2 (stored for verification, never plaintext).
    ///   4. Serializes everything into a <see cref="UserProfile"/> JSON blob.
    ///   5. Encrypts that blob to disk via <see cref="LocalFileCrypto"/>.
    ///
    /// On subsequent runs:
    ///   Decrypts the profile file with the user's password and loads the identity.
    /// </summary>
    internal class AccountManager
    {
        private const int RsaKeySize = 2048;
        private const int PasswordHashIterations = 600_000;
        private const int PasswordSaltSize = 32;
        private const int PasswordHashSize = 32;

        private static readonly SecureRandom SecureRng = new SecureRandom();

        private static readonly string DefaultProfileDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "P2PFT");

        private static readonly string DefaultProfilePath =
            Path.Combine(DefaultProfileDir, "identity.p2pf");

        private readonly string _userId;
        private readonly string _password;
        private readonly string _profilePath;

        /// <summary>
        /// The loaded or newly created user profile. Available after <see cref="Initialize"/>.
        /// </summary>
        public UserProfile Profile { get; private set; }

        /// <summary>
        /// The RSA key pair loaded from the profile. Available after <see cref="Initialize"/>.
        /// </summary>
        public AsymmetricCipherKeyPair RsaKeyPair { get; private set; }

        /// <param name="userId">Unique user/peer identifier.</param>
        /// <param name="password">Password used to encrypt/decrypt the local profile.</param>
        /// <param name="profilePath">Optional custom path for the encrypted profile file.</param>
        public AccountManager(string userId, string password, string profilePath = null)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("UserId must not be null or empty.", nameof(userId));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password must not be null or empty.", nameof(password));

            _userId = userId;
            _password = password;
            _profilePath = profilePath ?? DefaultProfilePath;
        }

        /// <summary>
        /// Loads an existing profile or creates a new one if none exists.
        /// </summary>
        public void Initialize()
        {
            if (File.Exists(_profilePath))
            {
                LoadProfile();
            }
            else
            {
                CreateProfile();
            }
        }

        /// <summary>
        /// Returns the public key fingerprint (SHA-256 of DER-encoded public key, lowercase hex).
        /// For out-of-band verification between peers.
        /// </summary>
        public string GetFingerprint()
        {
            if (Profile == null)
                throw new InvalidOperationException("Profile not initialized. Call Initialize() first.");

            return Profile.Fingerprint;
        }

        /// <summary>
        /// Exports the public key PEM for sharing with other peers.
        /// </summary>
        public string GetPublicKeyPem()
        {
            if (Profile == null)
                throw new InvalidOperationException("Profile not initialized. Call Initialize() first.");

            return Profile.PublicKeyPem;
        }

        /// <summary>
        /// Updates the IP address and port in the profile and re-saves to disk.
        /// </summary>
        public void UpdateNetworkInfo(string ipAddress, int port)
        {
            if (Profile == null)
                throw new InvalidOperationException("Profile not initialized. Call Initialize() first.");

            Profile.IpAddress = ipAddress;
            Profile.Port = port;
            SaveProfile();
        }

        /// <summary>
        /// Re-encrypts the profile file with a new password and updates the stored hash.
        /// </summary>
        public void ChangeVaultPassword(string newPassword)
        {
            if (Profile == null)
                throw new InvalidOperationException("Profile not initialized. Call Initialize() first.");
            if (string.IsNullOrEmpty(newPassword))
                throw new ArgumentException("New password must not be empty.", nameof(newPassword));

            byte[] salt = GenerateRandom(PasswordSaltSize);
            Profile.PasswordHash = HashPassword(newPassword, salt);
            Profile.PasswordSalt = Convert.ToBase64String(salt);

            byte[] json = SerializeProfile(Profile);
            LocalFileCrypto.EncryptToFile(json, newPassword, _userId, _profilePath);
        }

        /// <summary>
        /// Re-generates a fresh RSA-2048 key pair (key rotation) and saves the profile.
        /// Returns the new public key PEM for redistribution.
        /// </summary>
        public string RotateKeys(out AsymmetricCipherKeyPair oldKeyPair)
        {
            if (Profile == null)
                throw new InvalidOperationException("Profile not initialized. Call Initialize() first.");

            oldKeyPair = RsaKeyPair;
            RsaKeyPair = GenerateRsaKeyPair();

            Profile.PrivateKeyPem = ExportPrivateKeyPem(RsaKeyPair);
            Profile.PublicKeyPem = ExportPublicKeyPem(RsaKeyPair);
            Profile.Fingerprint = ComputeFingerprint(RsaKeyPair);

            SaveProfile();
            return Profile.PublicKeyPem;
        }

        /// <summary>
        /// Computes the SHA-256 fingerprint of an arbitrary DER-encoded public key.
        /// Useful for verifying a remote peer's identity.
        /// </summary>
        public static string ComputeFingerprintFromDer(byte[] derPublicKey)
        {
            if (derPublicKey == null || derPublicKey.Length == 0)
                throw new ArgumentException("DER public key must not be null or empty.", nameof(derPublicKey));

            var digest = new Sha256Digest();
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(derPublicKey, 0, derPublicKey.Length);
            digest.DoFinal(hash, 0);
            return BytesToHex(hash);
        }

        // ── Profile creation ────────────────────────────────────

        private void CreateProfile()
        {
            // Ensure directory exists
            string dir = Path.GetDirectoryName(_profilePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            // Generate RSA-2048 identity key pair
            RsaKeyPair = GenerateRsaKeyPair();

            // Hash password for verification (never store plaintext)
            byte[] salt = GenerateRandom(PasswordSaltSize);
            string passwordHash = HashPassword(_password, salt);

            // Detect local IP
            string localIp = GetLocalIpAddress();

            Profile = new UserProfile
            {
                UserId = _userId,
                PasswordHash = passwordHash,
                PasswordSalt = Convert.ToBase64String(salt),
                PrivateKeyPem = ExportPrivateKeyPem(RsaKeyPair),
                PublicKeyPem = ExportPublicKeyPem(RsaKeyPair),
                Fingerprint = ComputeFingerprint(RsaKeyPair),
                IpAddress = localIp,
                Port = 0,
                CreatedUtc = DateTime.UtcNow.ToString("o")
            };

            SaveProfile();
        }

        // ── Profile loading ─────────────────────────────────────

        private void LoadProfile()
        {
            // Verify file belongs to this user
            string fileUserId = LocalFileCrypto.ReadUserId(_profilePath);
            if (fileUserId != _userId)
                throw new UnauthorizedAccessException(
                    $"Profile belongs to user '{fileUserId}', expected '{_userId}'.");

            // Decrypt and deserialize
            byte[] json = LocalFileCrypto.DecryptFromFile(_profilePath, _password, _userId);
            Profile = DeserializeProfile(json);

            // Verify password against stored hash
            byte[] salt = Convert.FromBase64String(Profile.PasswordSalt);
            string computedHash = HashPassword(_password, salt);
            if (computedHash != Profile.PasswordHash)
                throw new UnauthorizedAccessException("Invalid password.");

            // Restore RSA key pair from stored PEM
            RsaKeyPair = ImportPrivateKeyPem(Profile.PrivateKeyPem);
        }

        // ── Profile persistence ─────────────────────────────────

        private void SaveProfile()
        {
            byte[] json = SerializeProfile(Profile);
            LocalFileCrypto.EncryptToFile(json, _password, _userId, _profilePath);
        }

        // ── RSA key generation (BouncyCastle) ───────────────────

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair()
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(SecureRng, RsaKeySize));
            return generator.GenerateKeyPair();
        }

        // ── RSA PEM export (BouncyCastle PemWriter) ─────────────

        private static string ExportPublicKeyPem(AsymmetricCipherKeyPair keyPair)
        {
            using (var sw = new StringWriter())
            {
                var pemWriter = new PemWriter(sw);
                pemWriter.WriteObject(keyPair.Public);
                pemWriter.Writer.Flush();
                return sw.ToString().TrimEnd();
            }
        }

        private static string ExportPrivateKeyPem(AsymmetricCipherKeyPair keyPair)
        {
            using (var sw = new StringWriter())
            {
                var pemWriter = new PemWriter(sw);
                pemWriter.WriteObject(keyPair.Private);
                pemWriter.Writer.Flush();
                return sw.ToString().TrimEnd();
            }
        }

        // ── RSA PEM import (BouncyCastle PemReader) ─────────────

        private static AsymmetricCipherKeyPair ImportPrivateKeyPem(string pem)
        {
            using (var sr = new StringReader(pem))
            {
                var pemReader = new PemReader(sr);
                object obj = pemReader.ReadObject();

                if (obj is AsymmetricCipherKeyPair keyPair)
                    return keyPair;

                if (obj is RsaPrivateCrtKeyParameters privateKey)
                {
                    var publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);
                    return new AsymmetricCipherKeyPair(publicKey, privateKey);
                }

                throw new InvalidOperationException("PEM does not contain a valid RSA private key.");
            }
        }

        /// <summary>
        /// Computes the SHA-256 fingerprint from the DER-encoded SubjectPublicKeyInfo.
        /// </summary>
        private static string ComputeFingerprint(AsymmetricCipherKeyPair keyPair)
        {
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            byte[] derPublicKey = publicKeyInfo.GetDerEncoded();
            return ComputeFingerprintFromDer(derPublicKey);
        }

        // ── Password hashing (BouncyCastle PBKDF2) ──────────────

        private static string HashPassword(string password, byte[] salt)
        {
            var generator = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            generator.Init(
                Encoding.UTF8.GetBytes(password),
                salt,
                PasswordHashIterations);

            var keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(PasswordHashSize * 8);
            return Convert.ToBase64String(keyParam.GetKey());
        }

        // ── JSON serialization (DataContractJsonSerializer) ─────

        private static byte[] SerializeProfile(UserProfile profile)
        {
            var serializer = new DataContractJsonSerializer(typeof(UserProfile));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, profile);
                return ms.ToArray();
            }
        }

        private static UserProfile DeserializeProfile(byte[] json)
        {
            var serializer = new DataContractJsonSerializer(typeof(UserProfile));
            using (var ms = new MemoryStream(json))
            {
                return (UserProfile)serializer.ReadObject(ms);
            }
        }

        // ── Helpers ─────────────────────────────────────────────

        private static string GetLocalIpAddress()
        {
            try
            {
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    // Doesn't actually send data — just determines the local route
                    socket.Connect("8.8.8.8", 65530);
                    var endpoint = socket.LocalEndPoint as IPEndPoint;
                    return endpoint?.Address.ToString() ?? "127.0.0.1";
                }
            }
            catch
            {
                return "127.0.0.1";
            }
        }

        private static byte[] GenerateRandom(int size)
        {
            byte[] buffer = new byte[size];
            SecureRng.NextBytes(buffer);
            return buffer;
        }

        private static string BytesToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 3 - 1);
            for (int i = 0; i < data.Length; i++)
            {
                if (i > 0) sb.Append(':');
                sb.Append(data[i].ToString("x2"));
            }
            return sb.ToString();
        }
    }
}
