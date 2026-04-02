using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml.
    /// Thin code-behind — delegates all logic to <see cref="DashboardViewModel"/>.
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly DashboardViewModel _vm;

        public MainWindow()
        {
            InitializeComponent();
            _vm = new DashboardViewModel();
            DataContext = _vm;

            _vm.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_vm.IsFirstRun)
                    || e.PropertyName == nameof(_vm.IsVaultInitialized))
                {
                    UpdateVaultLabels();
                }
            };
            UpdateVaultLabels();
        }

        // ── Vault labels ─────────────────────────────────────────

        private void UpdateVaultLabels()
        {
            if (_vm.IsFirstRun)
            {
                VaultTitle.Text = "Create Vault Password";
                VaultSubtitle.Text =
                    "Choose a strong password to protect your files at rest. " +
                    "This password will never be saved to disk.";
                VaultSubmitBtn.Content = "Create Vault";
            }
            else
            {
                VaultTitle.Text = "Unlock Vault";
                VaultSubtitle.Text =
                    "Enter your vault password to decrypt your stored files.";
                VaultSubmitBtn.Content = "Unlock";
            }
        }

        // ── Vault submit ─────────────────────────────────────────

        private void OnVaultSubmit(object sender, RoutedEventArgs e)
        {
            if (_vm.IsFirstRun)
                _vm.SetupVault(VaultPassword.Password, VaultPasswordConfirm.Password);
            else
                _vm.UnlockVault(VaultPassword.Password);
        }

        // ── Sidebar ──────────────────────────────────────────────

        private void OnRefreshPeers(object sender, RoutedEventArgs e)
        {
            _vm.RefreshPeerList();
        }

        // ── Shared files ─────────────────────────────────────────

        private void OnScanFiles(object sender, RoutedEventArgs e)
        {
            _vm.ScanSharedDirectory();
        }

        private void OnAddFile(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select file to share",
                Multiselect = false,
            };
            if (dlg.ShowDialog() == true)
            {
                _vm.AddSharedFile(dlg.FileName);
            }
        }

        private void OnRemoveFile(object sender, RoutedEventArgs e)
        {
            var el = sender as FrameworkElement;
            if (el != null && el.Tag is string filename)
                _vm.RemoveSharedFile(filename);
        }

        // ── Consent ──────────────────────────────────────────────

        private void OnReviewConsent(object sender, RoutedEventArgs e)
        {
            var el = sender as FrameworkElement;
            if (el != null && el.Tag is string requestId)
                _vm.ShowConsentModal(requestId);
        }

        private void OnConsentAccept(object sender, RoutedEventArgs e)
        {
            _vm.AcceptConsent();
        }

        private void OnConsentDeny(object sender, RoutedEventArgs e)
        {
            _vm.DenyConsent();
        }

        private void OnConsentBackdropClick(object sender, MouseButtonEventArgs e)
        {
            _vm.IsConsentModalOpen = false;
            _vm.ActiveConsent = null;
        }

        // ── Notification banner ──────────────────────────────────

        private void OnNotificationReview(object sender, RoutedEventArgs e)
        {
            _vm.ReviewNotification();
        }

        private void OnNotificationDismiss(object sender, RoutedEventArgs e)
        {
            _vm.DismissNotification();
        }

        // ── Peer detail ──────────────────────────────────────────

        private void OnBackHome(object sender, RoutedEventArgs e)
        {
            _vm.GoBackHome();
        }

        // ── Peer verification ────────────────────────────────────

        private void OnVerifyPeer(object sender, RoutedEventArgs e)
        {
            _vm.InitiateVerification();
        }

        private void OnConfirmVerification(object sender, RoutedEventArgs e)
        {
            _vm.ConfirmPeerVerification();
        }

        private void OnRejectVerification(object sender, RoutedEventArgs e)
        {
            _vm.RejectPeerVerification();
        }

        private void OnRevokeTrust(object sender, RoutedEventArgs e)
        {
            if (_vm.SelectedPeer == null) return;
            var result = MessageBox.Show(
                "Revoke trust for " + _vm.SelectedPeer.DisplayName + "?\n\n" +
                "You will need to re-verify their fingerprint before exchanging files.",
                "Revoke Trust", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (result == MessageBoxResult.Yes)
                _vm.RevokePeerTrust();
        }

        // ── Request file ─────────────────────────────────────────

        private void OnRequestFile(object sender, RoutedEventArgs e)
        {
            if (_vm.SelectedPeer == null) return;
            string filename = RequestFilenameInput.Text.Trim();
            if (string.IsNullOrEmpty(filename)) return;
            _vm.RequestFile(_vm.SelectedPeer.PeerId, filename);
            RequestFilenameInput.Text = "";
        }

        // ── Send file ────────────────────────────────────────────

        private void OnSendFile(object sender, RoutedEventArgs e)
        {
            if (_vm.SelectedPeer == null) return;
            var el = sender as FrameworkElement;
            if (el != null && el.Tag is string filename)
                _vm.SendFile(_vm.SelectedPeer.PeerId, filename);
        }

        // ── Fetch file list ───────────────────────────────────────

        private void OnFetchFileList(object sender, RoutedEventArgs e)
        {
            if (_vm.SelectedPeer == null) return;
            _vm.FetchFileList(_vm.SelectedPeer.PeerId);
        }

        private void OnRequestPeerFile(object sender, RoutedEventArgs e)
        {
            if (_vm.SelectedPeer == null) return;
            var el = sender as FrameworkElement;
            if (el != null && el.Tag is string filename)
                _vm.RequestFile(_vm.SelectedPeer.PeerId, filename);
        }

        // ── Vault download ───────────────────────────────────────

        private void OnDownloadVaultFile(object sender, RoutedEventArgs e)
        {
            var el = sender as FrameworkElement;
            if (el == null || !(el.Tag is string vaultFilename)) return;

            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog
                {
                    FileName = vaultFilename.Replace(".p2pf", ""),
                    Title = "Save decrypted file",
                };
                if (dlg.ShowDialog() == true)
                {
                    _vm.DecryptVaultFile(vaultFilename, dlg.FileName);
                    MessageBox.Show("File saved successfully.",
                        "Download Complete", MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to decrypt file: " + ex.Message,
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ── Change vault password ─────────────────────────────────

        private void OnChangeVaultPassword(object sender, RoutedEventArgs e)
        {
            var dlg = new ChangePasswordDialog { Owner = this };
            bool keepTrying = true;
            while (keepTrying && dlg.ShowDialog() == true)
            {
                string error = _vm.ChangeVaultPassword(
                    dlg.CurrentPasswordValue,
                    dlg.NewPasswordValue,
                    dlg.ConfirmPasswordValue);

                if (error == null)
                {
                    MessageBox.Show("Vault password changed successfully.",
                        "Password Changed", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                dlg = new ChangePasswordDialog { Owner = this };
                dlg.ShowError(error);
            }
        }

        // ── Own key rotation ─────────────────────────────────────

        private void OnRotateOwnKey(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "This will generate a new RSA-2048 key pair.\n\n" +
                "• Your old private key will be permanently destroyed.\n" +
                "• A REVOKE_KEY message will be sent to all verified peers.\n" +
                "• All peers will need to re-verify before transferring files.\n\n" +
                "Continue?",
                "Rotate Key Pair", MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
                _vm.RotateOwnKey();
        }

        // ── Window closing → stop discovery ──────────────────────

        private void OnWindowClosing(object sender,
            System.ComponentModel.CancelEventArgs e)
        {
            _vm.Shutdown();
        }
    }
}
