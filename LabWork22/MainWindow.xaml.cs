using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace LabWork22
{
    public partial class MainWindow : Window
    {
        private const string FileName = "password.txt";
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public MainWindow()
        {
            _key = Convert.FromBase64String("JK7LE/EGHIZoE9Sjl4m8gAnETqlMd0meELelqDicuGU=");
            _iv = Convert.FromBase64String("bv64Z5hKX+4s8WICRDqDVw==");
            InitializeComponent();
        }

        private async void MainWindow_OnLoadedAsync(object sender, RoutedEventArgs e)
        {
            await ShowData();
        }

        private async void AddButton_OnClick(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(SiteAppTextBox.Text) ||
                string.IsNullOrWhiteSpace(LoginTextBox.Text) ||
                string.IsNullOrWhiteSpace(PasswordTextBox.Text)) return;

            var logins = (await File.ReadAllLinesAsync(FileName))
                .Select(query => query.Split(";"))
                .Select(item => $"{item[0]};{item[1]}")
                .ToArray();
            
            if (logins.Contains($"{SiteAppTextBox.Text};{LoginTextBox.Text}")) return;
            
            if (!File.Exists(FileName))
                await using (File.Create(FileName)) {}

            var encryptPassword = await EncryptPasswordAsync(PasswordTextBox.Text);
            await File.AppendAllTextAsync(FileName, $"{SiteAppTextBox.Text};{LoginTextBox.Text};{encryptPassword}\n");
            await ShowData();
        }

        private void GeneratePasswordButton_OnClick(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(PasswordLengthIntegerUpDown.Text, out var passwordLength) || passwordLength <= 0) return;

            const string symbols = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-_+=;:,./?\|`~[]{}";
            var random = new Random();
            var builder = new StringBuilder();

            for (var i = 0; i < passwordLength; i++)
                builder.Append(symbols[random.Next(symbols.Length)]);

            PasswordTextBox.Text = builder.ToString();
        }

        private async Task<string> EncryptPasswordAsync(string password)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            byte[] encrypted;
            
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            await using (var msEncrypt = new MemoryStream())
            {
                await using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    await using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        await swEncrypt.WriteAsync(password);
                    }
                    
                    encrypted = msEncrypt.ToArray();
                }
            }
            
            return Convert.ToBase64String(encrypted);
        }

        private async Task<string> DecryptPasswordAsync(string encryptedPassword)
        {
            var encryptedPasswordByte = Convert.FromBase64String(encryptedPassword);
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            var decryptor = aes.CreateDecryptor();
            await using var msDecrypt = new MemoryStream(encryptedPasswordByte);
            await using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            return await srDecrypt.ReadToEndAsync();
        }

        private async Task ShowData()
        {
            if (!File.Exists(FileName))
                await using (File.Create(FileName)) {}

            var data = new List<object>();
            
            var lines = (await File.ReadAllLinesAsync(FileName))
                .Select(query => query.Split(";"))
                .ToArray();
            
            foreach (var item in lines)
            {
                var decryptPassword = await DecryptPasswordAsync(item[2]);
                data.Add(new
                {
                    SiteApp = item[0],
                    Login = item[1],
                    Password = decryptPassword
                });
            }
            
            DataListView.ItemsSource = data;
        }
    }
}