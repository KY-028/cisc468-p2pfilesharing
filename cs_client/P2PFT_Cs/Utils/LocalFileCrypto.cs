using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace P2PFT_Cs.Utils
{

    /// Local at-rest file encryption using AES-256-GCM + PBKDF2 key derivation.
    /// Encrypts received files with a user password before storing to disk.
    ///
    /// File format:
    ///   [ 4-byte magic "P2PF" ]
    ///   [ 1-byte version      ]
    ///   [ 4-byte userId length (little-endian) ]
    ///   [ userId bytes (UTF-8) ]
    ///   [ 32-byte PBKDF2 salt  ]
    ///   [ 12-byte GCM nonce    ]
    ///   [ ciphertext + 16-byte GCM tag ]
    ///
    /// PBKDF2: SHA-256, 600 000 iterations, 32-byte derived key.

    internal static class LocalFileCrypto
    {
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("P2PF");
        private const byte FormatVersion = 0x01;

        private const int SaltSize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const int Pbkdf2Iterations = 600_000;

        private static readonly SecureRandom SecureRng = new SecureRandom();


        public static void EncryptToFile(byte[] plaintext, string password, string userId, string outputPath)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw new ArgumentException("Plaintext must not be null or empty.", nameof(plaintext));
            ValidateInputs(password, userId);

            byte[] salt = GenerateRandom(SaltSize);
            byte[] nonce = GenerateRandom(NonceSize);
            byte[] key = DeriveKey(password, salt);

            try
            {
                byte[] encrypted = AesGcmEncrypt(key, nonce, plaintext);
                byte[] userIdBytes = Encoding.UTF8.GetBytes(userId);

                using (var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                using (var bw = new BinaryWriter(fs))
                {
                    // Header
                    bw.Write(Magic);                        // 4 bytes magic
                    bw.Write(FormatVersion);                // 1 byte version
                    bw.Write(userIdBytes.Length);            // 4 bytes userId length
                    bw.Write(userIdBytes);                   // N bytes userId
                    // Crypto parameters
                    bw.Write(salt);                          // 32 bytes salt
                    bw.Write(nonce);                         // 12 bytes nonce
                    // Payload
                    bw.Write(encrypted);                     // ciphertext + 16-byte tag
                }
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
            }
        }

        public static byte[] DecryptFromFile(string inputPath, string password, string expectedUserId)
        {
            if (string.IsNullOrEmpty(inputPath))
                throw new ArgumentException("Input path must not be null or empty.", nameof(inputPath));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password must not be null or empty.", nameof(password));

            using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var br = new BinaryReader(fs))
            {
        
                byte[] magic = br.ReadBytes(Magic.Length);
                if (!BytesEqual(magic, Magic))
                    throw new InvalidDataException("Invalid file: magic header mismatch.");

                byte version = br.ReadByte();
                if (version != FormatVersion)
                    throw new InvalidDataException($"Unsupported file format version: {version}.");

                int userIdLength = br.ReadInt32();
                if (userIdLength <= 0 || userIdLength > 1024)
                    throw new InvalidDataException("Invalid userId length in file header.");

                string fileUserId = Encoding.UTF8.GetString(br.ReadBytes(userIdLength));

                if (expectedUserId != null && fileUserId != expectedUserId)
                    throw new UnauthorizedAccessException(
                        $"File belongs to user '{fileUserId}', expected '{expectedUserId}'.");

                byte[] salt = br.ReadBytes(SaltSize);
                byte[] nonce = br.ReadBytes(NonceSize);


                long remaining = fs.Length - fs.Position;
                if (remaining < TagSize)
                    throw new InvalidDataException("File is too short to contain valid encrypted data.");

                byte[] encrypted = br.ReadBytes((int)remaining);


                byte[] key = DeriveKey(password, salt);
                try
                {
                    return AesGcmDecrypt(key, nonce, encrypted);
                }
                finally
                {
                    Array.Clear(key, 0, key.Length);
                }
            }
        }


        public static string ReadUserId(string inputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
                throw new ArgumentException("Input path must not be null or empty.", nameof(inputPath));

            using (var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
            using (var br = new BinaryReader(fs))
            {
                byte[] magic = br.ReadBytes(Magic.Length);
                if (!BytesEqual(magic, Magic))
                    throw new InvalidDataException("Invalid file: magic header mismatch.");

                br.ReadByte(); 

                int userIdLength = br.ReadInt32();
                if (userIdLength <= 0 || userIdLength > 1024)
                    throw new InvalidDataException("Invalid userId length in file header.");

                return Encoding.UTF8.GetString(br.ReadBytes(userIdLength));
            }
        }


        private static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext)
        {
            byte[] output = new byte[plaintext.Length + TagSize];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(key),
                TagSize * 8,
                nonce);

            cipher.Init(true, parameters);
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }

        private static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag)
        {
            byte[] plaintext = new byte[ciphertextWithTag.Length - TagSize];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(key),
                TagSize * 8,
                nonce);

            cipher.Init(false, parameters);
            int len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, plaintext, 0);
            cipher.DoFinal(plaintext, len); 

            return plaintext;
        }



        private static byte[] DeriveKey(string password, byte[] salt)
        {
            var generator = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            generator.Init(
                Encoding.UTF8.GetBytes(password),
                salt,
                Pbkdf2Iterations);

            var keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(KeySize * 8);
            return keyParam.GetKey();
        }


        private static byte[] GenerateRandom(int size)
        {
            byte[] buffer = new byte[size];
            SecureRng.NextBytes(buffer);
            return buffer;
        }

        private static void ValidateInputs(string password, string userId)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password must not be null or empty.", nameof(password));
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("UserId must not be null or empty.", nameof(userId));
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }
    }
}
