using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace P2PFT_Cs
{
    /// <summary>true ¡ú Visible, false ¡ú Collapsed.</summary>
    internal class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value is bool b && b) ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>true ¡ú Collapsed, false ¡ú Visible.</summary>
    internal class InverseBoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value is bool b && b) ? Visibility.Collapsed : Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>Status level string ¡ú background brush.</summary>
    internal class StatusLevelToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string level = value as string ?? "info";
            switch (level)
            {
                case "success": return FindBrush("SuccessBgBrush");
                case "warning": return FindBrush("WarningBgBrush");
                case "error":   return FindBrush("ErrorBgBrush");
                default:        return FindBrush("InfoBgBrush");
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }

        private static SolidColorBrush FindBrush(string key)
        {
            return Application.Current.FindResource(key) as SolidColorBrush ?? Brushes.Transparent;
        }
    }

    /// <summary>Status level string ¡ú foreground brush.</summary>
    internal class StatusLevelToForegroundConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string level = value as string ?? "info";
            switch (level)
            {
                case "success": return new SolidColorBrush(Color.FromRgb(0x15, 0x80, 0x3D));
                case "warning": return new SolidColorBrush(Color.FromRgb(0xA1, 0x62, 0x07));
                case "error":   return FindBrush("ErrorBrush");
                default:        return FindBrush("InfoBrush");
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }

        private static SolidColorBrush FindBrush(string key)
        {
            return Application.Current.FindResource(key) as SolidColorBrush ?? Brushes.Black;
        }
    }

    /// <summary>Peer status string ¡ú dot colour brush.</summary>
    internal class PeerStatusToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string status = value as string ?? "offline";
            switch (status)
            {
                case "online-verified":   return FindBrush("SuccessBrush");
                case "online-unverified": return FindBrush("WarningBrush");
                case "online-pending":    return FindBrush("AccentBrush");
                default:                  return FindBrush("ErrorBrush");
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }

        private static SolidColorBrush FindBrush(string key)
        {
            return Application.Current.FindResource(key) as SolidColorBrush ?? Brushes.Gray;
        }
    }

    /// <summary>Unix timestamp (double) ¡ú "HH:mm:ss" string.</summary>
    internal class UnixTimestampToStringConverter : IValueConverter
    {
        private static readonly DateTime Epoch =
            new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double ts && ts > 0)
                return Epoch.AddSeconds(ts).ToLocalTime().ToString("HH:mm:ss");
            return "";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>File size (long) ¡ú human-readable string.</summary>
    internal class FileSizeConverter : IValueConverter
    {
        private static readonly string[] Units = { "B", "KB", "MB", "GB" };

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            long bytes = 0;
            if (value is long l) bytes = l;
            else if (value is int i) bytes = i;

            if (bytes == 0) return "0 B";
            int idx = (int)Math.Floor(Math.Log(bytes, 1024));
            if (idx >= Units.Length) idx = Units.Length - 1;
            return (bytes / Math.Pow(1024, idx)).ToString("F1") + " " + Units[idx];
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}