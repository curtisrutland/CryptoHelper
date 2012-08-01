using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoHelper
{
    public static class Extensions
    {
        internal static void SetKey(this AesManaged aes, string password, byte[] salt)
        {
            var key = new Rfc2898DeriveBytes(password, salt);
            aes.Key = key.GetBytes(aes.KeySize / 8);
        }

        internal static byte[] GetIV(this Stream stream)
        {
            var ivLength = new byte[sizeof(int)];
            if (stream.Read(ivLength, 0, ivLength.Length) != ivLength.Length)
                throw new Exception("Stream did not contain properly formatted IV");
            var iv = new byte[BitConverter.ToInt32(ivLength, 0)];
            if (stream.Read(iv, 0, iv.Length) != iv.Length)
                throw new Exception("Could not read IV from stream.");
            return iv;
        }

        internal static byte[] ToByteArray(this string s, Encoding encoding)
        {
            return encoding.GetBytes(s);
        }

        public static string ToHashString(this byte[] hash)
        {
            return hash.Select(b => b.ToString("x2")).Aggregate((w, n) => w + n);
        }

        public static string ToBase64(this byte[] data)
        {
            return Convert.ToBase64String(data);
        }
    }
}