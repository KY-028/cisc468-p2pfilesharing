using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs.Tests
{
    [TestClass]
    public class TransmissionCryptoTests
    {
        // 32-byte (AES-256) test session key
        private static readonly byte[] ValidKey = new byte[32]
        {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
            0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
            0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
        };

        private const string FileName = "document.pdf";
        private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("Hello, P2PFT!");

        

        [TestMethod]
        public void EncryptDecrypt_RoundTrip_ReturnsOriginalPlaintext()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);
            byte[] result = TransmissionCrypto.Decrypt(ValidKey, blob, FileName, hash);

            CollectionAssert.AreEqual(Plaintext, result);
        }

        [TestMethod]
        public void Encrypt_ProducesDifferentCiphertexts_ForSamePlaintext()
        {
            // Each call uses a fresh random nonce
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob1 = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);
            string blob2 = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);

            Assert.AreNotEqual(blob1, blob2);
        }

        [TestMethod]
        public void Encrypt_OutputIsBase64()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);

         
            byte[] decoded = Convert.FromBase64String(blob);
            // nonce(12) + plaintext + tag(16)
            Assert.IsTrue(decoded.Length >= 12 + 1 + 16);
        }

   

        [TestMethod]
        public void Decrypt_ThrowsOnWrongFilename()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);

            Assert.ThrowsException<Org.BouncyCastle.Crypto.InvalidCipherTextException>(
                () => TransmissionCrypto.Decrypt(ValidKey, blob, "wrong.pdf", hash));
        }

        [TestMethod]
        public void Decrypt_ThrowsOnWrongHash()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);

            Assert.ThrowsException<Org.BouncyCastle.Crypto.InvalidCipherTextException>(
                () => TransmissionCrypto.Decrypt(ValidKey, blob, FileName, "deadbeef"));
        }

        [TestMethod]
        public void Decrypt_ThrowsOnWrongKey()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);

            byte[] wrongKey = new byte[32];
            Assert.ThrowsException<Org.BouncyCastle.Crypto.InvalidCipherTextException>(
                () => TransmissionCrypto.Decrypt(wrongKey, blob, FileName, hash));
        }

        [TestMethod]
        public void Decrypt_ThrowsOnTamperedCiphertext()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string blob = TransmissionCrypto.Encrypt(ValidKey, Plaintext, FileName, hash);

            byte[] raw = Convert.FromBase64String(blob);
            raw[15] ^= 0xFF; // flip a byte in the ciphertext
            string tampered = Convert.ToBase64String(raw);

            Assert.ThrowsException<Org.BouncyCastle.Crypto.InvalidCipherTextException>(
                () => TransmissionCrypto.Decrypt(ValidKey, tampered, FileName, hash));
        }

    

        [TestMethod]
        public void Encrypt_ThrowsOnNullKey()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            Assert.ThrowsException<ArgumentException>(
                () => TransmissionCrypto.Encrypt(null, Plaintext, FileName, hash));
        }

        [TestMethod]
        public void Encrypt_ThrowsOnShortKey()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            Assert.ThrowsException<ArgumentException>(
                () => TransmissionCrypto.Encrypt(new byte[16], Plaintext, FileName, hash));
        }

        [TestMethod]
        public void Encrypt_ThrowsOnNullPlaintext()
        {
            string hash = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            Assert.ThrowsException<ArgumentException>(
                () => TransmissionCrypto.Encrypt(ValidKey, null, FileName, hash));
        }

        [TestMethod]
        public void Decrypt_ThrowsOnEmptyBlob()
        {
            Assert.ThrowsException<ArgumentException>(
                () => TransmissionCrypto.Decrypt(ValidKey, "", FileName, "hash"));
        }

     

        [TestMethod]
        public void ComputeSha256Hex_KnownVector()
        {
            // SHA-256("") = e3b0c44298fc1c149afb...
            byte[] empty = Array.Empty<byte>();
            string hex = TransmissionCrypto.ComputeSha256Hex(empty);
            Assert.IsTrue(hex.StartsWith("e3b0c442"));
        }

        [TestMethod]
        public void ComputeSha256Hex_IsDeterministic()
        {
            string h1 = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            string h2 = TransmissionCrypto.ComputeSha256Hex(Plaintext);
            Assert.AreEqual(h1, h2);
        }
    }
}