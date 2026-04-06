using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs.Tests
{
    [TestClass]
    public class AccountManagerTests
    {
        private string _tempDir;

        [TestInitialize]
        public void Setup()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "P2PFT_AccTests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }

        private string ProfilePath() => Path.Combine(_tempDir, "identity.p2pf");

        private AccountManager CreateAndInit(string userId = "alice", string password = "pass123")
        {
            var am = new AccountManager(userId, password, ProfilePath());
            am.Initialize();
            return am;
        }



        [TestMethod]
        public void Initialize_CreatesProfileFile()
        {
            CreateAndInit();
            Assert.IsTrue(File.Exists(ProfilePath()));
        }

        [TestMethod]
        public void Initialize_SetsNonEmptyFingerprint()
        {
            var am = CreateAndInit();
            string fp = am.GetFingerprint();

            Assert.IsFalse(string.IsNullOrEmpty(fp));
        }

        [TestMethod]
        public void Initialize_SetsNonEmptyPublicKeyPem()
        {
            var am = CreateAndInit();
            string pem = am.GetPublicKeyPem();

            Assert.IsTrue(pem.Contains("PUBLIC KEY"));
        }

        [TestMethod]
        public void Initialize_FingerprintIsStableAcrossReloads()
        {
            var am1 = CreateAndInit();
            string fp1 = am1.GetFingerprint();

            // Reload from disk
            var am2 = new AccountManager("alice", "pass123", ProfilePath());
            am2.Initialize();
            string fp2 = am2.GetFingerprint();

            Assert.AreEqual(fp1, fp2);
        }



        [TestMethod]
        public void Initialize_ThrowsOnWrongPassword()
        {
            CreateAndInit("alice", "correctPass");

            var am = new AccountManager("alice", "wrongPass", ProfilePath());
            Assert.ThrowsException<UnauthorizedAccessException>(() => am.Initialize());
        }

        [TestMethod]
        public void Initialize_ThrowsOnWrongUserId()
        {
            CreateAndInit("alice", "pass123");

            var am = new AccountManager("bob", "pass123", ProfilePath());
            Assert.ThrowsException<UnauthorizedAccessException>(() => am.Initialize());
        }



        [TestMethod]
        public void UpdateNetworkInfo_PersistsAcrossReload()
        {
            var am = CreateAndInit();
            am.UpdateNetworkInfo("192.168.1.42", 9877);

            var am2 = new AccountManager("alice", "pass123", ProfilePath());
            am2.Initialize();

            Assert.AreEqual("192.168.1.42", am2.Profile.IpAddress);
            Assert.AreEqual(9877, am2.Profile.Port);
        }



        [TestMethod]
        public void RotateKeys_ProducesNewFingerprint()
        {
            var am = CreateAndInit();
            string fpBefore = am.GetFingerprint();

            am.RotateKeys(out _);
            string fpAfter = am.GetFingerprint();

            Assert.AreNotEqual(fpBefore, fpAfter);
        }

        [TestMethod]
        public void RotateKeys_NewKeyPersistsAcrossReload()
        {
            var am = CreateAndInit();
            am.RotateKeys(out _);
            string newPem = am.GetPublicKeyPem();

            var am2 = new AccountManager("alice", "pass123", ProfilePath());
            am2.Initialize();

            Assert.AreEqual(newPem, am2.GetPublicKeyPem());
        }



        [TestMethod]
        public void ChangeVaultPassword_AllowsLoginWithNewPassword()
        {
            var am = CreateAndInit("alice", "oldPass");
            am.ChangeVaultPassword("newPass");

            var am2 = new AccountManager("alice", "newPass", ProfilePath());
            am2.Initialize(); // should not throw

            Assert.AreEqual("alice", am2.Profile.UserId);
        }

        [TestMethod]
        public void ChangeVaultPassword_BlocksOldPassword()
        {
            var am = CreateAndInit("alice", "oldPass");
            am.ChangeVaultPassword("newPass");

            var am2 = new AccountManager("alice", "oldPass", ProfilePath());
            Assert.ThrowsException<UnauthorizedAccessException>(() => am2.Initialize());
        }



        [TestMethod]
        public void ComputeFingerprintFromDer_ThrowsOnNull()
        {
            Assert.ThrowsException<ArgumentException>(
                () => AccountManager.ComputeFingerprintFromDer(null));
        }

        [TestMethod]
        public void ComputeFingerprintFromDer_IsDeterministic()
        {
            byte[] der = new byte[64];
            new Random(1).NextBytes(der);

            string fp1 = AccountManager.ComputeFingerprintFromDer(der);
            string fp2 = AccountManager.ComputeFingerprintFromDer(der);

            Assert.AreEqual(fp1, fp2);
        }



        [TestMethod]
        public void Constructor_ThrowsOnEmptyUserId()
        {
            Assert.ThrowsException<ArgumentException>(
                () => new AccountManager("", "pass", ProfilePath()));
        }

        [TestMethod]
        public void Constructor_ThrowsOnEmptyPassword()
        {
            Assert.ThrowsException<ArgumentException>(
                () => new AccountManager("alice", "", ProfilePath()));
        }
    }
}