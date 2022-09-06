using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class RC2Provider : ICryptographicProvider
    {
        public byte[] Key;
        private byte[] IV;
        RC2 _rc2 = null;
        public RC2Provider(string Password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(Password),
                Encoding.UTF32.GetBytes(Password).Reverse().ToArray(),
                10);
            Key = oRfc2898DeriveBytes.GetBytes(16);
            IV = oRfc2898DeriveBytes.GetBytes(8);
            InitializeRC2();
        }

        public RC2Provider(byte[] Key, byte[] IV)
        {
            this.Key = Key;
            this.IV = IV;
            InitializeRC2();
        }

        private void InitializeRC2()
        {
            _rc2 = RC2.Create();
            _rc2.Key = Key;
            _rc2.IV = IV;
        }

        public byte[] Decrypt(byte[] bMessage)
        {
            ICryptoTransform dec = _rc2.CreateDecryptor(_rc2.Key, _rc2.IV);
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
            ICryptoTransform enc = _rc2.CreateEncryptor(_rc2.Key, _rc2.IV);
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
