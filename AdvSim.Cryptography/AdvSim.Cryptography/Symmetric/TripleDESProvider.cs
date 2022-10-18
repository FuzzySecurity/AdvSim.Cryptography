using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    /// <summary>
    /// 3DES Cryptographic Provider
    /// </summary>
    public class TripleDESProvider : ICryptographicProvider
    {
        private byte[] _key;
        private byte[] _iv;
        private TripleDES _tripledes;

        /// <summary>
        /// Derive a 3DES cryptographic object based on the given secret.
        /// </summary>
        /// <param name="password">Shared secret to derive encryption material from.</param>
        public TripleDESProvider(string password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(password),
                Encoding.UTF32.GetBytes(password).Reverse().ToArray(), 10);
            _key = oRfc2898DeriveBytes.GetBytes(24);
            _iv = oRfc2898DeriveBytes.GetBytes(8);
            InitializeTripleDES();
        }

        /// <summary>
        /// Create a 3DES cryptographic object using the specified encryption material.
        /// </summary>
        /// <param name="key">Encryption key used to encrypt and decrypt data with.</param>
        /// <param name="iv">The initialization vector used in key derivation.</param>
        public TripleDESProvider(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
            if (_key.Length != 24)
            {
                throw new ArgumentException($"Key length must be 24 bytes, not {key.Length}");
            }

            if (_iv.Length != 8)
            {
                throw new ArgumentException($"Key length must be 8 bytes, not {iv.Length}");
            }
            InitializeTripleDES();
        }

        /// <summary>
        /// Set instanced variables on the 3DES object.
        /// </summary>
        private void InitializeTripleDES()
        {
            _tripledes = TripleDES.Create();
            _tripledes.Key = _key;
            _tripledes.IV = _iv;
        }

        /// <summary>
        /// Decrypt a previously encrypted 3DES message.
        /// </summary>
        /// <param name="bMessage">3DES encrypted message.</param>
        /// <returns>Plaintext message as a byte array.</returns>
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

        /// <summary>
        /// Encrypts a plaintext message using 3DES algorithm.
        /// </summary>
        /// <param name="bMessage">Plaintext message to encrypt.</param>
        /// <returns>Encrypted message as a byte array.</returns>
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
