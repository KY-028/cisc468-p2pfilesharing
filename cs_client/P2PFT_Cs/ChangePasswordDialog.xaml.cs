using System.Windows;

namespace P2PFT_Cs
{
    public partial class ChangePasswordDialog : Window
    {
        public string CurrentPasswordValue => CurrentPassword.Password;
        public string NewPasswordValue => NewPassword.Password;
        public string ConfirmPasswordValue => ConfirmPassword.Password;

        public ChangePasswordDialog()
        {
            InitializeComponent();
        }

        private void OnConfirm(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }

        private void OnCancel(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        public void ShowError(string message)
        {
            ErrorText.Text = message;
            ErrorBanner.Visibility = Visibility.Visible;
        }
    }
}
