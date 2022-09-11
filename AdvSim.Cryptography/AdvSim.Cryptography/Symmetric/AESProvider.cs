using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class AESProvider : ICryptographicProvider
    {
        public byte[] Key { get; private set; }
        private byte[] IV;
        private Aes _aes;
        public AESProvider(string Password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(Password),
                Encoding.UTF32.GetBytes(Password).Reverse().ToArray(), 
                10);
            Key = oRfc2898DeriveBytes.GetBytes(32);
            IV = oRfc2898DeriveBytes.GetBytes(16);
            InitializeAes();
        }

        public AESProvider(byte[] Key, byte[] IV)
        {
            this.Key = Key;
            this.IV = IV;

            if (Key.Length != 32)
            {
                throw new ArgumentException($"Key must be 32 bytes in length, but got {Key.Length}");
            }

            if (IV.Length != 16)
            {
                throw new ArgumentException($"IV must be 16 bytes in length, but got {Key.Length}");
            }

            InitializeAes();
        }

        private void InitializeAes()
        {
            _aes = Aes.Create();
            _aes.Key = Key;
            _aes.IV = IV;
        }
        public byte[] Decrypt(byte[] bMessage)
        {
            ICryptoTransform dec = _aes.CreateDecryptor(_aes.Key, _aes.IV);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Write))
                {
                    using (BinaryWriter sw = new BinaryWriter(cs))
                    {
                        sw.Write(bMessage);
                    }
                    return ms.ToArray();
                }
            }
        }

        public byte[] Encrypt(byte[] bMessage)
        {
            ICryptoTransform enc = _aes.CreateEncryptor(_aes.Key, _aes.IV);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                {
                    using (BinaryWriter sw = new BinaryWriter(cs))
                    {
                        sw.Write(bMessage);
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}
