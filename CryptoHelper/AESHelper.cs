using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoHelper
{
    public static class AESHelper
    {
        private static readonly byte[] DefaultSalt = new byte[] { 0x41, 0x45, 0x53, 0x48, 0x65, 0x6c, 0x70, 0x65, 0x72 };

        public static byte[] Encrypt(string text, string password, byte[] salt = null)
        {
            if (string.IsNullOrEmpty(text)) throw new ArgumentNullException("text");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            if (salt == null) salt = DefaultSalt;
            var aes = new AesManaged();

            byte[] encryptedData;

            try
            {
                aes.SetKey(password, salt);
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (var ms = new MemoryStream())
                {
                    ms.Write(BitConverter.GetBytes(aes.IV.Length), 0, sizeof(int));
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                        sw.Write(text);
                    encryptedData = ms.ToArray();
                }
            }
            finally
            {
                aes.Clear();
            }

            return encryptedData;
        }

        public static string EncryptToBase64(string text, string password)
        {
            var encryptedData = Encrypt(text, password);
            return encryptedData.ToBase64();
        }

        public static string Decrypt(byte[] encryptedData, string password, byte[] salt = null)
        {
            if (encryptedData == null) throw new ArgumentNullException("encryptedData");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            if (salt == null) salt = DefaultSalt;
            var aes = new AesManaged();

            string text;

            try
            {
                aes.SetKey(password, salt);
                using (var ms = new MemoryStream(encryptedData))
                {
                    aes.IV = ms.GetIV();
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                        text = sr.ReadToEnd();
                }
            }
            finally
            {
                aes.Clear();
            }

            return text;
        }

        public static string DecryptFromBase64(string b64String, string password)
        {
            if (b64String == null) throw new ArgumentNullException("b64String");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            var encryptedData = Convert.FromBase64String(b64String);
            return Decrypt(encryptedData, password);
        }
    }
}
