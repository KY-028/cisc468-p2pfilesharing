using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs.Tests
{
    [TestClass]
    public class LocalFileCryptoTests
    {
        private string _tempDir;

        [TestInitialize]
        public void Setup()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "P2PFT_Tests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }

        private string TempFile() => Path.Combine(_tempDir, Guid.NewGuid() + ".p2pf");



        [TestMethod]
        public void EncryptDecrypt_RoundTrip_ReturnsOriginalBytes()
        {
            byte[] original = Encoding.UTF8.GetBytes("Hello, encrypted world!");
            string path = TempFile();

            LocalFileCrypto.EncryptToFile(original, "password123", "user_a", path);
            byte[] result = LocalFileCrypto.DecryptFromFile(path, "password123", "user_a");

            CollectionAssert.AreEqual(original, result);
        }

        [TestMethod]
        public void EncryptDecrypt_LargePayload_RoundTrip()
        {
            byte[] original = new byte[512 * 1024]; // 512 KB
            new Random(42).NextBytes(original);
            string path = TempFile();

            LocalFileCrypto.EncryptToFile(original, "strongPass!", "user_b", path);
            byte[] result = LocalFileCrypto.DecryptFromFile(path, "strongPass!", "user_b");

            CollectionAssert.AreEqual(original, result);
        }



        [TestMethod]
        public void Decrypt_ThrowsOnWrongPassword()
        {
            byte[] data = Encoding.UTF8.GetBytes("secret");
            string path = TempFile();
            LocalFileCrypto.EncryptToFile(data, "correctPass", "user_a", path);

            Assert.ThrowsException<Org.BouncyCastle.Crypto.InvalidCipherTextException>(
                () => LocalFileCrypto.DecryptFromFile(path, "wrongPass", "user_a"));
        }



        [TestMethod]
        public void Decrypt_ThrowsOnUserIdMismatch()
        {
            byte[] data = Encoding.UTF8.GetBytes("secret");
            string path = TempFile();
            LocalFileCrypto.EncryptToFile(data, "password", "alice", path);

            Assert.ThrowsException<UnauthorizedAccessException>(
                () => LocalFileCrypto.DecryptFromFile(path, "password", "bob"));
        }

        [TestMethod]
        public void Decrypt_SkipsUserIdCheck_WhenNull()
        {
            byte[] data = Encoding.UTF8.GetBytes("secret");
            string path = TempFile();
            LocalFileCrypto.EncryptToFile(data, "password", "alice", path);

            // null = skip userId check
            byte[] result = LocalFileCrypto.DecryptFromFile(path, "password", null);
            CollectionAssert.AreEqual(data, result);
        }



        [TestMethod]
        public void Decrypt_ThrowsOnCorruptedMagicHeader()
        {
            byte[] data = Encoding.UTF8.GetBytes("secret");
            string path = TempFile();
            LocalFileCrypto.EncryptToFile(data, "password", "user_a", path);

            byte[] raw = File.ReadAllBytes(path);
            raw[0] ^= 0xFF; // corrupt the magic
            File.WriteAllBytes(path, raw);

            Assert.ThrowsException<InvalidDataException>(
                () => LocalFileCrypto.DecryptFromFile(path, "password", "user_a"));
        }


        [TestMethod]
        public void ReadUserId_ReturnsCorrectUserId()
        {
            byte[] data = Encoding.UTF8.GetBytes("content");
            string path = TempFile();
            LocalFileCrypto.EncryptToFile(data, "pass", "my_user", path);

            string userId = LocalFileCrypto.ReadUserId(path);
            Assert.AreEqual("my_user", userId);
        }


        [TestMethod]
        public void EncryptToFile_ThrowsOnNullPlaintext()
        {
            Assert.ThrowsException<ArgumentException>(
                () => LocalFileCrypto.EncryptToFile(null, "pass", "user", TempFile()));
        }

        [TestMethod]
        public void EncryptToFile_ThrowsOnEmptyPassword()
        {
            Assert.ThrowsException<ArgumentException>(
                () => LocalFileCrypto.EncryptToFile(new byte[] { 1 }, "", "user", TempFile()));
        }

        [TestMethod]
        public void DecryptFromFile_ThrowsOnMissingFile()
        {
            Assert.ThrowsException<FileNotFoundException>(
                () => LocalFileCrypto.DecryptFromFile(TempFile(), "pass", "user"));
        }
    }
}