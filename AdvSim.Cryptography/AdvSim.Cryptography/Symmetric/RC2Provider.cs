using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    /// <summary>
    /// Wrapper object to encrypt and decrypt messages using RC2 encryption.
    /// </summary>
    public class RC2Provider : ICryptographicProvider
    {
        /// <summary>
        /// Key used to encrypt and decrypt data.
        /// </summary>
        public byte[] Key { get; private set; }
        /// <summary>
        /// Initialization vector used to derive the encryption key.
        /// </summary>
        private byte[] _iv;
        private RC2 _rc2 = null;

        /// <summary>
        /// Create an RC2 cryptor object based on a shared secret.
        /// </summary>
        /// <param name="password">Shared secret to derive the encryption key from.</param>
        public RC2Provider(string password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(password),
                Encoding.UTF32.GetBytes(password).Reverse().ToArray(),
                10);
            Key = oRfc2898DeriveBytes.GetBytes(16);
            _iv = oRfc2898DeriveBytes.GetBytes(8);
            InitializeRC2();
        }

        public RC2Provider(byte[] key, byte[] iv)
        {
            this.Key = key;
            this._iv = iv;
            if (key.Length != 16)
            {
                throw new ArgumentException($"Key must be 16 bytes, but got {key.Length}");
            }
            if (iv.Length != 8)
            {
                throw new ArgumentException($"IV must be 8 bytes, but got {iv.Length}");
            }
            InitializeRC2();
        }

        /// <summary>
        /// Set internal instanced variables based on constructor arguments.
        /// </summary>
        private void InitializeRC2()
        {
            _rc2 = RC2.Create();
            _rc2.Key = Key;
            _rc2.IV = _iv;
        }

        /// <summary>
        /// Decrypt a message encrypted with the same RC2 secret.
        /// </summary>
        /// <param name="bMessage">RC2 encrypted message.</param>
        /// <returns>Plaintext message as a byte array.</returns>
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

        /// <summary>
        /// Encrypt a message based on the RC2 secret.
        /// </summary>
        /// <param name="bMessage">Plaintext message to be encrypted.</param>
        /// <returns>Encryped RC2 message as a byte array.</returns>
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
