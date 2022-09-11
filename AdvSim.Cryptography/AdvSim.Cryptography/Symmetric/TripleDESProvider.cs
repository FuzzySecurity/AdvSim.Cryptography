using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class TripleDESProvider : ICryptographicProvider
    {
        private byte[] _key;
        private byte[] _iv;
        private TripleDES _tripledes;
        public TripleDESProvider(string Password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(Password),
                Encoding.UTF32.GetBytes(Password).Reverse().ToArray(), 10);
            _key = oRfc2898DeriveBytes.GetBytes(24);
            _iv = oRfc2898DeriveBytes.GetBytes(8);
            InitializeTripleDES();
        }

        public TripleDESProvider(byte[] Key, byte[] IV)
        {
            _key = Key;
            _iv = IV;
            if (_key.Length != 24)
            {
                throw new ArgumentException($"Key length must be 24 bytes, not {Key.Length}");
            }

            if (_iv.Length != 8)
            {
                throw new ArgumentException($"Key length must be 8 bytes, not {IV.Length}");
            }
            InitializeTripleDES();
        }

        private void InitializeTripleDES()
        {
            _tripledes = TripleDES.Create();
            _tripledes.Key = _key;
            _tripledes.IV = _iv;
        }
        public byte[] Decrypt(byte[] bMessage)
        {
            ICryptoTransform dec = _tripledes.CreateDecryptor(_tripledes.Key, _tripledes.IV);
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
            ICryptoTransform enc = _tripledes.CreateEncryptor(_tripledes.Key, _tripledes.IV);
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
