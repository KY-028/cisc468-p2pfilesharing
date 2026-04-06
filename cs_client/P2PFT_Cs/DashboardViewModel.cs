using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs
{
    /// <summary>
    /// ViewModel that connects the WPF UI to <see cref="FileTransfer"/>,
    /// <see cref="PeerDiscovery"/>, and <see cref="PeerValidation"/>.
    /// </summary>
    internal class DashboardViewModel : INotifyPropertyChanged
    {
        private readonly DispatcherTimer _pollTimer;

        //Vault state 
        private bool _isVaultUnlocked;
        private bool _isVaultInitialized;
        private string _vaultError;

        //Identity
        private string _peerId;
        private string _fingerprint;
        private string _vaultPassword;

        // Peer detail
        private PeerViewModel _selectedPeer;
        private bool _isPeerViewActive;

        //Consent modal 
        private FileTransfer.ConsentRecord _activeConsent;

        //Notification
        private bool _hasNotification;
        private string _notificationMessage;
        private string _notificationRequestId;
        private DispatcherTimer _notificationTimer;

        //Engine 
        private FileTransfer _fileTransfer;
        private AccountManager _account;
        private PeerDiscovery _discovery;
        private PeerValidation _validation;
        private ManifestStorage _manifests;

        //Paths
        private static readonly string SharedDir =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "shared");

        private const int DefaultTcpPort = 9877;

        //Observable collections
        public ObservableCollection<PeerViewModel> Peers { get; }
            = new ObservableCollection<PeerViewModel>();
        public ObservableCollection<SharedFileViewModel> SharedFiles { get; }
            = new ObservableCollection<SharedFileViewModel>();
        public ObservableCollection<ConsentViewModel> PendingConsents { get; }
            = new ObservableCollection<ConsentViewModel>();
        public ObservableCollection<StatusViewModel> StatusLog { get; }
            = new ObservableCollection<StatusViewModel>();
        public ObservableCollection<TransferViewModel> Transfers { get; }
            = new ObservableCollection<TransferViewModel>();
        public ObservableCollection<SharedFileViewModel> SendableFiles { get; }
            = new ObservableCollection<SharedFileViewModel>();
        public ObservableCollection<string> VaultFiles { get; }
            = new ObservableCollection<string>();
        public ObservableCollection<PeerFileViewModel> PeerFiles { get; }
            = new ObservableCollection<PeerFileViewModel>();

        // Constructor

        public DashboardViewModel()
        {
            _peerId = "(not set)";
            _fingerprint = "(not generated yet)";
            _isVaultInitialized = CheckVaultInitialized();

            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _pollTimer.Tick += (s, e) => RefreshFromEngine();
        }

        //  Properties
        
        public string PeerId
        {
            get { return _peerId; }
            set { _peerId = value; OnPropertyChanged(); }
        }

        public string Fingerprint
        {
            get { return _fingerprint; }
            set { _fingerprint = value; OnPropertyChanged(); }
        }

        public string NetworkStatus
        {
            get
            {
                if (_discovery != null) return "�� Listening on port " + DefaultTcpPort;
                return "�� Offline";
            }
        }

        public bool IsVaultUnlocked
        {
            get { return _isVaultUnlocked; }
            set { _isVaultUnlocked = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsVaultLocked)); }
        }

        public bool IsVaultLocked { get { return !_isVaultUnlocked; } }

        public bool IsVaultInitialized
        {
            get { return _isVaultInitialized; }
            set { _isVaultInitialized = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsFirstRun)); }
        }

        public bool IsFirstRun { get { return !_isVaultInitialized; } }

        public string VaultError
        {
            get { return _vaultError; }
            set { _vaultError = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasVaultError)); }
        }

        public bool HasVaultError { get { return !string.IsNullOrEmpty(_vaultError); } }

        public bool HasNoPeers { get { return Peers.Count == 0; } }

        public PeerViewModel SelectedPeer
        {
            get { return _selectedPeer; }
            set
            {
                _selectedPeer = value;
                IsPeerViewActive = value != null;
                OnPropertyChanged();
                RefreshPeerDetailLists();
            }
        }

        public bool IsPeerViewActive
        {
            get { return _isPeerViewActive; }
            set { _isPeerViewActive = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsHomeViewActive)); }
        }

        public bool IsHomeViewActive { get { return !_isPeerViewActive; } }

        public bool IsConsentModalOpen
        {
            get { return _isConsentModalOpen; }
            set { _isConsentModalOpen = value; OnPropertyChanged(); }
        }

        public FileTransfer.ConsentRecord ActiveConsent
        {
            get { return _activeConsent; }
            set { _activeConsent = value; OnPropertyChanged(); }
        }


       //  Vault
        public void SetupVault(string password, string confirmPassword)
        {
            VaultError = null;
            if (password.Length < 8) { VaultError = "Password must be at least 8 characters."; return; }
            if (password != confirmPassword) { VaultError = "Passwords do not match."; return; }

            try
            {
                string userId = "user-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                _account = new AccountManager(userId, password);
                _account.Initialize();
                PeerId = _account.Profile.UserId;
                Fingerprint = _account.GetFingerprint();
                _vaultPassword = password;
                IsVaultInitialized = true;
                IsVaultUnlocked = true;
                InitialiseEngine(userId, password);
            }
            catch (Exception ex) { VaultError = "Setup failed: " + ex.Message; }
        }

        public void UnlockVault(string password)
        {
            VaultError = null;
            if (string.IsNullOrEmpty(password)) { VaultError = "Please enter your vault password."; return; }

            try
            {
                string profilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "P2PFT", "identity.p2pf");
                string userId = LocalFileCrypto.ReadUserId(profilePath);
                _account = new AccountManager(userId, password);
                _account.Initialize();
                PeerId = _account.Profile.UserId;
                Fingerprint = _account.GetFingerprint();
                _vaultPassword = password;
                IsVaultUnlocked = true;
                InitialiseEngine(userId, password);
            }
            catch (Exception) { VaultError = "Incorrect password or corrupted vault config."; }
        }

        /// <summary>
        /// Changes the vault password. Re-encrypts the identity profile and all vault files.
        /// Returns null on success, or an error message string on failure.
        /// </summary>
        public string ChangeVaultPassword(string currentPassword, string newPassword, string confirmPassword)
        {
            if (string.IsNullOrEmpty(currentPassword)) return "Please enter your current password.";
            if (currentPassword != _vaultPassword) return "Current password is incorrect.";
            if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 8)
                return "New password must be at least 8 characters.";
            if (newPassword != confirmPassword) return "New passwords do not match.";

            try
            {
                _account.ChangeVaultPassword(newPassword);
                _fileTransfer?.UpdatePassword(newPassword);
                _vaultPassword = newPassword;
                return null;
            }
            catch (Exception ex) { return "Failed to change password: " + ex.Message; }
        }

        //  Engine bootstrap
        
        private void InitialiseEngine(string userId, string password)
        {
            _fileTransfer = new FileTransfer(userId, password, userId);
            _fileTransfer.ConsentReceived += OnConsentReceived;
            _fileTransfer.HandshakeNeeded += OnHandshakeNeeded;

            _validation = new PeerValidation(userId, _account, _fileTransfer);
            _validation.PeerVerified += OnPeerVerified;
            _validation.PeerKeyRotated += OnPeerKeyRotated;
            _validation.VerificationRequired += OnVerificationRequired;

            _discovery = new PeerDiscovery(userId, DefaultTcpPort, _fileTransfer, _validation);
            _discovery.PeerDiscovered += OnPeerDiscovered;
            _discovery.PeerOffline += OnPeerOffline;

            string dataDir = AppDomain.CurrentDomain.BaseDirectory;
            _manifests = new ManifestStorage(dataDir);
            _discovery.SetManifestStorage(_manifests);
            _discovery.SetSharedFilesCallback(GetSharedFileList);

            _discovery.Start();

            OnPropertyChanged(nameof(NetworkStatus));

            // Restore previously trusted peers (skip ourselves)
            foreach (var rec in _validation.GetAllPeers())
            {
                if (rec.PeerId == userId) continue;
                if (!Peers.Any(p => p.PeerId == rec.PeerId))
                {
                    Peers.Add(new PeerViewModel
                    {
                        PeerId = rec.PeerId,
                        DisplayName = rec.PeerId,
                        Trusted = rec.Trusted,
                        Online = false,
                        Fingerprint = rec.Fingerprint ?? "unknown",
                    });
                }
            }
            OnPropertyChanged(nameof(HasNoPeers));

            if (!Directory.Exists(SharedDir))
                Directory.CreateDirectory(SharedDir);

            ScanSharedDirectory();
            _pollTimer.Start();
        }

        //  Discovery events (background threads �� Dispatcher)
        
        private void OnPeerDiscovered(string peerId, string address, int port)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                bool isTrusted = _validation != null && _validation.IsTrusted(peerId);
                string fp = _validation != null ? _validation.GetFingerprint(peerId) : null;

                var existing = Peers.FirstOrDefault(p => p.PeerId == peerId);
                if (existing != null)
                {
                    existing.Address = address;
                    existing.Port = port;
                    existing.Online = true;
                    existing.Trusted = isTrusted;
                    if (!string.IsNullOrEmpty(fp)) existing.Fingerprint = fp;
                }
                else
                {
                    Peers.Add(new PeerViewModel
                    {
                        PeerId = peerId,
                        DisplayName = peerId,
                        Address = address,
                        Port = port,
                        Trusted = isTrusted,
                        Online = true,
                        Fingerprint = fp ?? "unknown",
                    });
                }
                OnPropertyChanged(nameof(HasNoPeers));
            }));
        }

        private void OnPeerOffline(string peerId)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                var existing = Peers.FirstOrDefault(p => p.PeerId == peerId);
                if (existing != null) existing.Online = false;
            }));
        }

        private void OnPeerVerified(string peerId)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                var existing = Peers.FirstOrDefault(p => p.PeerId == peerId);
                if (existing != null) existing.Trusted = true;
            }));

            // Auto-fetch file list after verification (like Python client)
            if (_fileTransfer != null && _manifests != null)
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try { _fileTransfer.RequestFileListFromPeer(peerId, _manifests); }
                    catch { }
                });
            }
        }

        private void OnPeerKeyRotated(string peerId)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                var existing = Peers.FirstOrDefault(p => p.PeerId == peerId);
                if (existing != null)
                {
                    existing.Trusted = false;
                    string fp = _validation != null ? _validation.GetFingerprint(peerId) : null;
                    if (!string.IsNullOrEmpty(fp)) existing.Fingerprint = fp;
                }
            }));
        }

        private void OnVerificationRequired(string peerId, string verificationCode)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                var existing = Peers.FirstOrDefault(p => p.PeerId == peerId);
                if (existing != null)
                {
                    existing.VerificationCode = verificationCode;
                    string fp = _validation != null ? _validation.GetFingerprint(peerId) : null;
                    if (!string.IsNullOrEmpty(fp)) existing.Fingerprint = fp;
                }
                ShowNotification("Peer " + peerId + " wants to pair — verify fingerprint", null);
            }));
        }

        private void OnConsentReceived(FileTransfer.ConsentRecord consent)
        {
            Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
            {
                // Immediately add to PendingConsents without waiting for poll
                if (!PendingConsents.Any(c => c.RequestId == consent.RequestId))
                {
                    PendingConsents.Add(new ConsentViewModel
                    {
                        RequestId = consent.RequestId,
                        PeerName = consent.PeerName,
                        Action = consent.Action,
                        Filename = consent.Filename,
                        Timestamp = consent.Timestamp,
                    });
                }

                string action = consent.Action == "file_send" ? "send you" : "request";
                ShowNotification(consent.PeerName + " wants to " + action +
                                 " \"" + consent.Filename + "\"", consent.RequestId);
            }));
        }

        private void OnHandshakeNeeded(string peerId)
        {
            var peer = Peers.FirstOrDefault(p => p.PeerId == peerId);
            if (peer == null || string.IsNullOrEmpty(peer.Address)) return;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try { _validation.InitiateHandshake(peerId, peer.Address, peer.Port); }
                catch { }
            });
        }

        // Notification helpers

        public bool HasNotification
        {
            get { return _hasNotification; }
            set { _hasNotification = value; OnPropertyChanged(); }
        }

        public string NotificationMessage
        {
            get { return _notificationMessage; }
            set { _notificationMessage = value; OnPropertyChanged(); }
        }

        public string NotificationRequestId
        {
            get { return _notificationRequestId; }
            set { _notificationRequestId = value; OnPropertyChanged(); }
        }

        private void ShowNotification(string message, string requestId)
        {
            NotificationMessage = message;
            NotificationRequestId = requestId;
            HasNotification = true;

            // Flash the taskbar
            FlashTaskbar();

            // Auto-dismiss after 10 seconds
            if (_notificationTimer != null)
                _notificationTimer.Stop();
            _notificationTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
            _notificationTimer.Tick += (s, e) =>
            {
                _notificationTimer.Stop();
                HasNotification = false;
            };
            _notificationTimer.Start();
        }

        public void DismissNotification()
        {
            HasNotification = false;
            if (_notificationTimer != null) _notificationTimer.Stop();
        }

        public void ReviewNotification()
        {
            if (!string.IsNullOrEmpty(NotificationRequestId))
                ShowConsentModal(NotificationRequestId);
            DismissNotification();
        }

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

        [StructLayout(LayoutKind.Sequential)]
        private struct FLASHWINFO
        {
            public uint cbSize;
            public IntPtr hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        private static void FlashTaskbar()
        {
            try
            {
                var mainWindow = Application.Current?.MainWindow;
                if (mainWindow == null) return;
                var helper = new WindowInteropHelper(mainWindow);
                var info = new FLASHWINFO
                {
                    cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO)),
                    hwnd = helper.Handle,
                    dwFlags = 0x03 | 0x0C, // FLASHW_ALL | FLASHW_TIMERNOFG
                    uCount = 3,
                    dwTimeout = 0,
                };
                FlashWindowEx(ref info);
            }
            catch { }
        }

      //  Shared file management
       
        public void ScanSharedDirectory()
        {
            SharedFiles.Clear();
            if (!Directory.Exists(SharedDir)) return;

            foreach (string filePath in Directory.GetFiles(SharedDir))
            {
                byte[] data = File.ReadAllBytes(filePath);
                string hash = TransmissionCrypto.ComputeSha256Hex(data);
                SharedFiles.Add(new SharedFileViewModel
                {
                    Filename = Path.GetFileName(filePath),
                    FilePath = filePath,
                    Size = data.LongLength,
                    Sha256Hash = hash,
                });
            }
            RefreshPeerDetailLists();
        }

        public void AddSharedFile(string sourceFilePath)
        {
            if (!Directory.Exists(SharedDir))
                Directory.CreateDirectory(SharedDir);

            string filename = Path.GetFileName(sourceFilePath);
            string destPath = Path.Combine(SharedDir, filename);

            if (!File.Exists(destPath))
                File.Copy(sourceFilePath, destPath);

            ScanSharedDirectory();
        }

        public void RemoveSharedFile(string filename)
        {
            var item = SharedFiles.FirstOrDefault(f => f.Filename == filename);
            if (item != null) SharedFiles.Remove(item);
            RefreshPeerDetailLists();
        }

     
        //  Peer actions
      

        public void GoBackHome()
        {
            SelectedPeer = null;
        }

        public void RefreshPeerList()
        {
            // Force update trust status from the validation store
            if (_validation == null) return;
            foreach (var peer in Peers)
            {
                peer.Trusted = _validation.IsTrusted(peer.PeerId);
                string fp = _validation.GetFingerprint(peer.PeerId);
                if (!string.IsNullOrEmpty(fp)) peer.Fingerprint = fp;
            }
        }

        public void RequestFile(string peerId, string filename)
        {
            if (_fileTransfer == null) return;
            _fileTransfer.RequestFileFromPeer(peerId, filename);
            RefreshFromEngine();
        }

        public void FetchFileList(string peerId)
        {
            if (_fileTransfer == null || _manifests == null) return;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    _fileTransfer.RequestFileListFromPeer(peerId, _manifests);
                    Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                    {
                        RefreshPeerDetailLists();
                    }));
                }
                catch { }
            });
        }

        private List<DataObj.FileInfo> GetSharedFileList()
        {
            var result = new List<DataObj.FileInfo>();
            string sharedDir = SharedDir;
            if (!Directory.Exists(sharedDir)) return result;

            foreach (string filePath in Directory.GetFiles(sharedDir))
            {
                byte[] data = File.ReadAllBytes(filePath);
                string hash = TransmissionCrypto.ComputeSha256Hex(data);

                // Sign the hash with our RSA-PSS key (for third-party verification)
                string signature = null;
                if (_validation != null)
                {
                    byte[] hashBytes = System.Text.Encoding.UTF8.GetBytes(hash);
                    signature = _validation.SignData(hashBytes);
                }

                result.Add(new DataObj.FileInfo
                {
                    Filename = Path.GetFileName(filePath),
                    Size = data.LongLength,
                    FileHash = hash,
                    OwnerId = _peerId,
                    Signature = signature,
                });
            }
            return result;
        }

        public void SendFile(string peerId, string filename)
        {
            if (_fileTransfer == null) return;
            var shared = SharedFiles.FirstOrDefault(f => f.Filename == filename);
            if (shared == null) return;
            _fileTransfer.SendConsentOffer(peerId, shared.Filename,
                                           shared.Sha256Hash, shared.FilePath);
            RefreshFromEngine();
        }

        //  Peer verification
       
        /// <summary>
        /// Initiates verification: generates the code on-demand if needed (like Python's /api/verify-peer).
        /// </summary>
        public void InitiateVerification()
        {
            if (_validation == null || SelectedPeer == null) return;

            // If code already shown, nothing to do
            if (SelectedPeer.HasVerificationCode) return;

            string myFp = _account?.GetFingerprint();
            string theirFp = _validation.GetFingerprint(SelectedPeer.PeerId);

            // If we don't have the peer's fingerprint yet, initiate a handshake
            // (like Python's /api/verify-peer which handshakes on-demand)
            if (string.IsNullOrEmpty(myFp))
            {
                MessageBox.Show(
                    "Local identity not available.",
                    "Verification Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrEmpty(theirFp))
            {
                // Trigger handshake — it will call RaiseVerificationIfNeeded on
                // completion, which fires VerificationRequired and sets the code.
                System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        _validation.InitiateHandshake(
                            SelectedPeer.PeerId, SelectedPeer.Address, SelectedPeer.Port);
                    }
                    catch (Exception ex)
                    {
                        Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                        {
                            MessageBox.Show(
                                "Handshake failed: " + ex.Message,
                                "Verification Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }));
                    }
                });
                return;
            }

            string code = PeerValidation.GenerateVerificationCode(myFp, theirFp);
            SelectedPeer.VerificationCode = code;
        }

        /// <summary>
        /// User confirmed the displayed code matches — send VERIFY_CONFIRM to peer.
        /// </summary>
        public void ConfirmPeerVerification()
        {
            if (_validation == null || SelectedPeer == null) return;
            _validation.ConfirmVerification(
                SelectedPeer.PeerId, SelectedPeer.Address, SelectedPeer.Port);
            SelectedPeer.VerificationCode = null;
        }

        /// <summary>
        /// User rejected the verification — send VERIFY_REJECT to peer.
        /// </summary>
        public void RejectPeerVerification()
        {
            if (_validation == null || SelectedPeer == null) return;
            _validation.RejectVerification(
                SelectedPeer.PeerId, SelectedPeer.Address, SelectedPeer.Port);
            SelectedPeer.VerificationCode = null;
            MessageBox.Show(
                "Verification rejected.\nThe session with this peer has been destroyed.",
                "Verification Rejected", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        public void RevokePeerTrust()
        {
            if (_validation == null || SelectedPeer == null) return;
            _validation.RevokeTrust(SelectedPeer.PeerId);
            SelectedPeer.Trusted = false;
        }

        public void RotateOwnKey()
        {
            if (_account == null || _validation == null || _fileTransfer == null) return;

            try
            {
                // 1. Save old fingerprint before rotation
                string oldFingerprint = _account.GetFingerprint();

                // 2. Rotate keys — get old key pair for cross-signing
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair oldKeyPair;
                string newPubKeyPem = _account.RotateKeys(out oldKeyPair);

                // 3. Cross-sign: sign the new public key PEM with the old private key
                byte[] newPubKeyBytes = System.Text.Encoding.UTF8.GetBytes(newPubKeyPem);
                string crossSignature = _validation.CrossSign(oldKeyPair.Private, newPubKeyBytes);

                // 4. Clear all session keys (they were derived with old identity)
                _fileTransfer.ClearAllSessionKeys();

                // 5. Broadcast REVOKE_KEY to all online peers
                var msg = new DataObj.RevokeKeyMessage(new DataObj.RevokeKeyPayload
                {
                    PeerId = _peerId,
                    NewPublicKey = newPubKeyPem,
                    CrossSignature = crossSignature,
                    OldFingerprint = oldFingerprint,
                    Reason = "key_rotation",
                });
                _fileTransfer.BroadcastToAllPeers(msg);

                // 6. Update local UI state
                Fingerprint = _account.GetFingerprint();
                OnPropertyChanged(nameof(Fingerprint));

                // 7. Mark all peers as untrusted (they need to re-verify)
                foreach (var peer in Peers)
                    peer.Trusted = false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Key rotation failed: " + ex.Message,
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        //  Consent
        
        public void ShowConsentModal(string requestId)
        {
            if (_fileTransfer == null) return;
            var consent = _fileTransfer.GetPendingConsents()
                .FirstOrDefault(c => c.RequestId == requestId);
            if (consent != null)
            {
                ActiveConsent = consent;
                IsConsentModalOpen = true;
            }
        }

        public void AcceptConsent()
        {
            if (_fileTransfer == null || ActiveConsent == null) return;
            _fileTransfer.OnConsentApproved(ActiveConsent.RequestId);
            IsConsentModalOpen = false;
            ActiveConsent = null;
            RefreshFromEngine();
        }

        public void DenyConsent()
        {
            if (_fileTransfer == null || ActiveConsent == null) return;
            _fileTransfer.OnConsentDenied(ActiveConsent.RequestId);
            IsConsentModalOpen = false;
            ActiveConsent = null;
            RefreshFromEngine();
        }

        //  Vault download
        
        public void DecryptVaultFile(string vaultFilename, string destinationPath)
        {
            string receivedDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "received");
            string encPath = Path.Combine(receivedDir, vaultFilename);
            byte[] decrypted = LocalFileCrypto.DecryptFromFile(encPath, _vaultPassword, PeerId);
            File.WriteAllBytes(destinationPath, decrypted);
        }

        //  Polling
        
        private void RefreshFromEngine()
        {
            if (_fileTransfer == null) return;

            // Consents
            var consents = _fileTransfer.GetPendingConsents();
            PendingConsents.Clear();
            foreach (var c in consents)
            {
                PendingConsents.Add(new ConsentViewModel
                {
                    RequestId = c.RequestId,
                    PeerName = c.PeerName,
                    Action = c.Action,
                    Filename = c.Filename,
                    Timestamp = c.Timestamp,
                });
            }

            // Transfers
            var transfers = _fileTransfer.GetTransfers();
            Transfers.Clear();
            foreach (var t in transfers)
            {
                Transfers.Add(new TransferViewModel
                {
                    TransferId = t.TransferId,
                    Filename = t.Filename,
                    PeerId = t.PeerId,
                    Direction = t.Direction,
                    Status = t.Status,
                    Error = t.Error,
                    Timestamp = t.Timestamp,
                });
            }

            // Status log
            var statuses = _fileTransfer.GetStatusLog();
            StatusLog.Clear();
            foreach (var s in statuses.Reverse())
            {
                StatusLog.Add(new StatusViewModel
                {
                    Message = s.Message,
                    Level = s.Level,
                    Timestamp = s.Timestamp,
                });
                if (StatusLog.Count >= 20) break;
            }

            // Vault files
            VaultFiles.Clear();
            string receivedDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "received");
            if (Directory.Exists(receivedDir))
            {
                foreach (string file in Directory.GetFiles(receivedDir, "*.p2pf"))
                    VaultFiles.Add(Path.GetFileName(file));
            }

            // Refresh peer trust from validation
            if (_validation != null)
            {
                foreach (var peer in Peers)
                {
                    peer.Trusted = _validation.IsTrusted(peer.PeerId);
                    string fp = _validation.GetFingerprint(peer.PeerId);
                    if (!string.IsNullOrEmpty(fp)) peer.Fingerprint = fp;
                }
            }

            RefreshPeerDetailLists();
        }

        private void RefreshPeerDetailLists()
        {
            if (SelectedPeer == null) return;
            SendableFiles.Clear();
            foreach (var f in SharedFiles)
                SendableFiles.Add(f);

            PeerFiles.Clear();
            if (_manifests != null)
            {
                var files = _manifests.Get(SelectedPeer.PeerId);
                foreach (var f in files)
                {
                    PeerFiles.Add(new PeerFileViewModel
                    {
                        Filename = f.Filename,
                        Size = f.Size,
                        Sha256Hash = f.FileHash ?? "",
                    });
                }
            }
        }

        //  Shutdown
       
        public void Shutdown()
        {
            _pollTimer.Stop();
            if (_discovery != null)
            {
                _discovery.Stop();
                _discovery = null;
            }
        }

        //  Helpers
       
        private bool CheckVaultInitialized()
        {
            string profilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "P2PFT", "identity.p2pf");
            return File.Exists(profilePath);
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            if (PropertyChanged != null)
                PropertyChanged(this, new PropertyChangedEventArgs(name));
        }
    }

    //  View-model items
    
    internal class PeerViewModel : INotifyPropertyChanged
    {
        private string _address = "";
        private int _port;
        private bool _trusted;
        private bool _online;
        private string _fingerprint = "unknown";
        private string _verificationCode;

        public string PeerId { get; set; }
        public string DisplayName { get; set; }

        public string Address
        {
            get { return _address; }
            set { _address = value; Notify(); Notify("AddressDisplay"); }
        }

        public int Port
        {
            get { return _port; }
            set { _port = value; Notify(); Notify("AddressDisplay"); }
        }

        public bool Trusted
        {
            get { return _trusted; }
            set { _trusted = value; Notify(); Notify("StatusClass"); Notify("StatusLabel"); Notify("TrustLabel"); }
        }

        public bool Online
        {
            get { return _online; }
            set { _online = value; Notify(); Notify("StatusClass"); Notify("StatusLabel"); Notify("TrustLabel"); }
        }

        public string Fingerprint
        {
            get { return _fingerprint; }
            set { _fingerprint = value; Notify(); }
        }

        public string VerificationCode
        {
            get { return _verificationCode; }
            set { _verificationCode = value; Notify(); Notify("HasVerificationCode"); }
        }

        public bool HasVerificationCode
        {
            get { return !string.IsNullOrEmpty(_verificationCode); }
        }

        public string StatusClass
        {
            get
            {
                if (Online && Trusted) return "online-verified";
                if (Online && !Trusted) return "online-unverified";
                return "offline";
            }
        }

        public string StatusLabel
        {
            get
            {
                if (Online && Trusted) return "Verified �� Online";
                if (Online && !Trusted) return "Unverified �� Online";
                return "Offline";
            }
        }

        public string TrustLabel
        {
            get
            {
                if (Trusted) return "? Trusted (verified)";
                return "? Not verified";
            }
        }

        public string AddressDisplay
        {
            get { return string.IsNullOrEmpty(_address) ? "unknown" : _address + ":" + _port; }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        private void Notify([CallerMemberName] string name = null)
        {
            if (PropertyChanged != null)
                PropertyChanged(this, new PropertyChangedEventArgs(name));
        }
    }

    internal class SharedFileViewModel
    {
        public string Filename { get; set; }
        public string FilePath { get; set; }
        public long Size { get; set; }
        public string Sha256Hash { get; set; }

        public string HashShort
        {
            get
            {
                if (Sha256Hash != null && Sha256Hash.Length > 12)
                    return Sha256Hash.Substring(0, 12) + "��";
                return Sha256Hash ?? "";
            }
        }

        public string SizeAndHash
        {
            get { return FormatSize(Size) + " �� " + HashShort; }
        }

        private static string FormatSize(long bytes)
        {
            if (bytes == 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB" };
            int idx = (int)Math.Floor(Math.Log(bytes, 1024));
            if (idx >= units.Length) idx = units.Length - 1;
            return (bytes / Math.Pow(1024, idx)).ToString("F1") + " " + units[idx];
        }
    }

    internal class ConsentViewModel
    {
        public string RequestId { get; set; }
        public string PeerName { get; set; }
        public string Action { get; set; }
        public string Filename { get; set; }
        public double Timestamp { get; set; }
        public string ActionDescription { get { return Action == "file_send" ? "send you" : "request"; } }
    }

    internal class StatusViewModel
    {
        public string Message { get; set; }
        public string Level { get; set; }
        public double Timestamp { get; set; }
    }

    internal class TransferViewModel
    {
        public string TransferId { get; set; }
        public string Filename { get; set; }
        public string PeerId { get; set; }
        public string Direction { get; set; }
        public string Status { get; set; }
        public string Error { get; set; }
        public double Timestamp { get; set; }
        public string DirectionIcon { get { return Direction == "incoming" ? "??" : "??"; } }
    }

    internal class PeerFileViewModel
    {
        public string Filename { get; set; }
        public long Size { get; set; }
        public string Sha256Hash { get; set; }

        public string SizeDisplay
        {
            get
            {
                if (Size == 0) return "0 B";
                string[] units = { "B", "KB", "MB", "GB" };
                int idx = (int)Math.Floor(Math.Log(Size, 1024));
                if (idx >= units.Length) idx = units.Length - 1;
                return (Size / Math.Pow(1024, idx)).ToString("F1") + " " + units[idx];
            }
        }

        public string HashShort
        {
            get
            {
                if (Sha256Hash != null && Sha256Hash.Length > 12)
                    return Sha256Hash.Substring(0, 12) + "…";
                return Sha256Hash ?? "";
            }
        }
    }
}