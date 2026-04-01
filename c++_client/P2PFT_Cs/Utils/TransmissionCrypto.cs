using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace P2PFT_Cs.Utils
{
    /// <summary>
    /// AES-256-GCM authenticated encryption for peer-to-peer file transmission.
    /// 
    /// Wire format (all concatenated):
    ///   [ 12-byte nonce | ciphertext | 16-byte GCM tag ]
    /// 
    /// AAD is "filename:sha256_hash" — authenticated but not encrypted.
    /// Session keys are 32-byte HKDF-derived values from the STS handshake.
    /// </summary>
    internal static class TransmissionCrypto
    {
        // NIST SP 800-38D recommended nonce length for GCM
        private const int NonceSize = 12;

        // 128-bit authentication tag
        private const int TagSize = 16;

        // AES-256 key length
        private const int KeySize = 32;

        /// <summary>
        /// Encrypts plaintext using AES-256-GCM with the given session key and AAD.
        /// </summary>
        /// <param name="sessionKey">32-byte HKDF-derived session key from STS handshake.</param>
        /// <param name="plaintext">The raw data to encrypt.</param>
        /// <param name="filename">Original filename (used to build AAD).</param>
        /// <param name="sha256Hash">Hex-encoded SHA-256 hash of the plaintext (used to build AAD).</param>
        /// <returns>Base64-encoded blob: [nonce | ciphertext | tag].</returns>
        public static string Encrypt(byte[] sessionKey, byte[] plaintext, string filename, string sha256Hash)
        {
            ValidateKey(sessionKey);
            if (plaintext == null || plaintext.Length == 0)
                throw new ArgumentException("Plaintext must not be null or empty.", nameof(plaintext));

            byte[] nonce = GenerateNonce();
            byte[] aad = BuildAad(filename, sha256Hash);

            // GCM output = ciphertext + appended tag
            byte[] output = new byte[plaintext.Length + TagSize];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(sessionKey),
                TagSize * 8,  // tag size in bits
                nonce,
                aad);

            cipher.Init(true, parameters);
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);

            // Wire format: [nonce | ciphertext | tag]
            byte[] blob = new byte[NonceSize + output.Length];
            Buffer.BlockCopy(nonce, 0, blob, 0, NonceSize);
            Buffer.BlockCopy(output, 0, blob, NonceSize, output.Length);

            return Convert.ToBase64String(blob);
        }

        /// <summary>
        /// Decrypts a Base64-encoded AES-256-GCM blob using the given session key and AAD.
        /// Verifies the authentication tag and AAD integrity automatically.
        /// </summary>
        /// <param name="sessionKey">32-byte HKDF-derived session key from STS handshake.</param>
        /// <param name="base64Blob">Base64-encoded wire blob: [nonce | ciphertext | tag].</param>
        /// <param name="filename">Original filename (used to rebuild AAD).</param>
        /// <param name="sha256Hash">Hex-encoded SHA-256 hash to verify against (used to rebuild AAD).</param>
        /// <returns>Decrypted plaintext bytes.</returns>
        public static byte[] Decrypt(byte[] sessionKey, string base64Blob, string filename, string sha256Hash)
        {
            ValidateKey(sessionKey);
            if (string.IsNullOrEmpty(base64Blob))
                throw new ArgumentException("Blob must not be null or empty.", nameof(base64Blob));

            byte[] blob = Convert.FromBase64String(base64Blob);

            if (blob.Length < NonceSize + TagSize)
                throw new CryptographicException("Blob is too short to contain a valid nonce and tag.");

            // Extract nonce and ciphertext+tag
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(blob, 0, nonce, 0, NonceSize);

            int encryptedLength = blob.Length - NonceSize;
            byte[] encrypted = new byte[encryptedLength];
            Buffer.BlockCopy(blob, NonceSize, encrypted, 0, encryptedLength);

            byte[] aad = BuildAad(filename, sha256Hash);

            // Plaintext is encrypted data minus the tag
            byte[] plaintext = new byte[encryptedLength - TagSize];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(sessionKey),
                TagSize * 8,
                nonce,
                aad);

            cipher.Init(false, parameters);
            int len = cipher.ProcessBytes(encrypted, 0, encryptedLength, plaintext, 0);
            cipher.DoFinal(plaintext, len);  // throws InvalidCipherTextException if tag is invalid

            return plaintext;
        }

        /// <summary>
        /// Computes the SHA-256 hash of data and returns it as a lowercase hex string.
        /// Use this to build the hash value before encryption and to verify after decryption.
        /// </summary>
        public static string ComputeSha256Hex(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Builds the AAD string: "filename:sha256_hash" encoded as UTF-8 bytes.
        /// This metadata is authenticated but not encrypted by GCM.
        /// </summary>
        private static byte[] BuildAad(string filename, string sha256Hash)
        {
            if (string.IsNullOrEmpty(filename))
                throw new ArgumentException("Filename must not be null or empty.", nameof(filename));
            if (string.IsNullOrEmpty(sha256Hash))
                throw new ArgumentException("SHA-256 hash must not be null or empty.", nameof(sha256Hash));

            return Encoding.UTF8.GetBytes(filename + ":" + sha256Hash);
        }

        /// <summary>
        /// Generates a cryptographically secure 12-byte random nonce.
        /// </summary>
        private static byte[] GenerateNonce()
        {
            byte[] nonce = new byte[NonceSize];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(nonce);
            }
            return nonce;
        }

        private static void ValidateKey(byte[] sessionKey)
        {
            if (sessionKey == null || sessionKey.Length != KeySize)
                throw new ArgumentException(
                    $"Session key must be exactly {KeySize} bytes (AES-256).",
                    nameof(sessionKey));
        }
    }
}
