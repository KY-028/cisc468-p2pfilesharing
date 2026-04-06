using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using P2PFT_Cs;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs.Tests
{
    /// <summary>
    /// Tests for the pure, side-effect-free logic in PeerValidation:
    /// trust management, fingerprint verification, and verification code generation.
    /// Full STS handshake tests require two live TCP endpoints and are covered by integration tests.
    /// </summary>
    [TestClass]
    public class PeerValidationTests
    {
        private string _tempDir;
        private AccountManager _account;
        private FileTransfer _fileTransfer;
        private PeerValidation _validation;

        [TestInitialize]
        public void Setup()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "P2PFT_PVTests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);

            string profilePath = Path.Combine(_tempDir, "identity.p2pf");
            _account = new AccountManager("test_peer", "testpass", profilePath);
            _account.Initialize();

            _fileTransfer = new FileTransfer("test_peer", "testpass", "test_peer");
            _validation = new PeerValidation("test_peer", _account, _fileTransfer);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }

      

        [TestMethod]
        public void RegisterPeerKey_ReturnsTrueForValidPem()
        {
            string pem = _account.GetPublicKeyPem();
            bool result = _validation.RegisterPeerKey("peer_a", pem, null);
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void RegisterPeerKey_StoredPeerIsNotTrustedByDefault()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);
            Assert.IsFalse(_validation.IsTrusted("peer_a"));
        }

        [TestMethod]
        public void RegisterPeerKey_ReturnsFalseOnEmptyPem()
        {
            bool result = _validation.RegisterPeerKey("peer_a", "", null);
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void RegisterPeerKey_ReturnsFalseOnFingerprintMismatch()
        {
            string pem = _account.GetPublicKeyPem();
            bool result = _validation.RegisterPeerKey("peer_a", pem, "aa:bb:cc");
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void RegisterPeerKey_PreservesTrustOnSameKey()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);
            _validation.ConfirmTrust("peer_a");

           
            _validation.RegisterPeerKey("peer_a", pem, null);
            Assert.IsTrue(_validation.IsTrusted("peer_a"));
        }



        [TestMethod]
        public void ConfirmTrust_MakesPeerTrusted()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);
            _validation.ConfirmTrust("peer_a");

            Assert.IsTrue(_validation.IsTrusted("peer_a"));
        }

        [TestMethod]
        public void RevokeTrust_MakesPeerUntrusted()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);
            _validation.ConfirmTrust("peer_a");
            _validation.RevokeTrust("peer_a");

            Assert.IsFalse(_validation.IsTrusted("peer_a"));
        }

        [TestMethod]
        public void ConfirmTrust_RaisesPeerVerifiedEvent()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);

            string raised = null;
            _validation.PeerVerified += id => raised = id;
            _validation.ConfirmTrust("peer_a");

            Assert.AreEqual("peer_a", raised);
        }

        [TestMethod]
        public void ConfirmTrust_ReturnsFalseForUnknownPeer()
        {
            bool result = _validation.ConfirmTrust("unknown_peer");
            Assert.IsFalse(result);
        }


        [TestMethod]
        public void RemovePeer_PeerNoLongerReturned()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);
            _validation.RemovePeer("peer_a");

            Assert.IsNull(_validation.GetPublicKeyPem("peer_a"));
        }


        [TestMethod]
        public void GetFingerprint_ReturnsNonNullAfterRegistration()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);

            string fp = _validation.GetFingerprint("peer_a");
            Assert.IsNotNull(fp);
        }

        [TestMethod]
        public void GetFingerprint_ReturnsNullForUnknownPeer()
        {
            Assert.IsNull(_validation.GetFingerprint("ghost"));
        }

     

        [TestMethod]
        public void VerifyFingerprint_ReturnsTrueForCorrectFingerprint()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);
            string fp = _validation.GetFingerprint("peer_a");

            Assert.IsTrue(_validation.VerifyFingerprint("peer_a", fp));
        }

        [TestMethod]
        public void VerifyFingerprint_ReturnsFalseForWrongFingerprint()
        {
            string pem = _account.GetPublicKeyPem();
            _validation.RegisterPeerKey("peer_a", pem, null);

            Assert.IsFalse(_validation.VerifyFingerprint("peer_a", "aa:bb:cc"));
        }


        [TestMethod]
        public void GenerateVerificationCode_ReturnsNonNull()
        {
            string code = PeerValidation.GenerateVerificationCode("fp_a", "fp_b");
            Assert.IsNotNull(code);
        }

        [TestMethod]
        public void GenerateVerificationCode_IsSymmetric()
        {
            // The code must be identical regardless of who is the initiator
            string code1 = PeerValidation.GenerateVerificationCode("fp_alice", "fp_bob");
            string code2 = PeerValidation.GenerateVerificationCode("fp_bob", "fp_alice");

            Assert.AreEqual(code1, code2);
        }

        [TestMethod]
        public void GenerateVerificationCode_HasCorrectFormat()
        {
            // Expected: 6 groups of 5 digits separated by spaces  ¡ú 35 chars total
            string code = PeerValidation.GenerateVerificationCode("fp_a", "fp_b");
            string[] groups = code.Split(' ');

            Assert.AreEqual(6, groups.Length);
            foreach (string group in groups)
            {
                Assert.AreEqual(5, group.Length);
                Assert.IsTrue(long.TryParse(group, out _), $"Group '{group}' is not numeric.");
            }
        }

        [TestMethod]
        public void GenerateVerificationCode_IsDeterministic()
        {
            string code1 = PeerValidation.GenerateVerificationCode("fp_a", "fp_b");
            string code2 = PeerValidation.GenerateVerificationCode("fp_a", "fp_b");

            Assert.AreEqual(code1, code2);
        }

        [TestMethod]
        public void GenerateVerificationCode_DifferentInputsProduceDifferentCodes()
        {
            string code1 = PeerValidation.GenerateVerificationCode("fp_a", "fp_b");
            string code2 = PeerValidation.GenerateVerificationCode("fp_a", "fp_c");

            Assert.AreNotEqual(code1, code2);
        }

        [TestMethod]
        public void GenerateVerificationCode_ReturnsNullOnEmptyInput()
        {
            Assert.IsNull(PeerValidation.GenerateVerificationCode("", "fp_b"));
            Assert.IsNull(PeerValidation.GenerateVerificationCode("fp_a", null));
        }
    }
}