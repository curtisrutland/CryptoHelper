using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoHelper
{
    public static class Hash
    {
        //private static readonly byte[] DefaultSalt = new byte[] { 0x41, 0x45, 0x53, 0x48, 0x65, 0x6c, 0x70, 0x65, 0x72 };

        public static byte[] With<T>(string data, IEnumerable<byte> salt = null) where T : HashAlgorithm, new()
        {
            var bytes = salt != null
                ? salt.Concat(data.ToByteArray(Encoding.UTF8)).ToArray()
                : data.ToByteArray(Encoding.UTF8);
            return new T().ComputeHash(bytes);
        }

        public static byte[] With<T>(string data, string salt) where T : HashAlgorithm, new()
        {
            return With<T>(data, salt.ToByteArray(Encoding.UTF8));
        }
    }
}
