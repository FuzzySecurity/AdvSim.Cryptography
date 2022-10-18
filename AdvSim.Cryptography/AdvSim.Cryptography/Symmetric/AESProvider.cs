using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    /// <summary>
    /// Wrapper object to encrypt and decrypt messages using
    /// AES encryption.
    /// </summary>
    public class AESProvider : ICryptographicProvider
    {
        /// <summary>
        /// The secret key used to encrypt messages.
        /// </summary>
        public byte[] Key { get; private set; }
        /// <summary>
        /// Initialization vector used for deriving the secret key.
        /// </summary>
        private byte[] _iv;
        private Aes _aes;

        /// <summary>
        /// Create a new AES encryptor object whose keys are derived
        /// from a shared password.
        /// </summary>
        /// <param name="password">String to derive the Key's secret bytes from.</param>
        public AESProvider(string password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(password),
                Encoding.UTF32.GetBytes(password).Reverse().ToArray(), 
                10);
            Key = oRfc2898DeriveBytes.GetBytes(32);
            _iv = oRfc2898DeriveBytes.GetBytes(16);
            InitializeAes();
        }

        /// <summary>
        /// Creates a new AES encryptor object with a pre-defined secret
        /// key and initialization vector.
        /// </summary>
        /// <param name="key">Secret key to encrypt and decrypt messages with.</param>
        /// <param name="iv">Initialization vector used to derive aforementioned key.</param>
        public AESProvider(byte[] key, byte[] iv)
        {
            this.Key = key;
            this._iv = iv;

            if (key.Length != 32)
            {
                throw new ArgumentException($"Key must be 32 bytes in length, but got {key.Length}");
            }

            if (iv.Length != 16)
            {
                throw new ArgumentException($"IV must be 16 bytes in length, but got {key.Length}");
            }

            InitializeAes();
        }

        /// <summary>
        /// Instantiate instanced variables for encryption and decryption.
        /// </summary>
        private void InitializeAes()
        {
            _aes = Aes.Create();
            _aes.Key = Key;
            _aes.IV = _iv;
        }
        /// <summary>
        /// Decrypt messages previously encrypted using the shared secret.
        /// </summary>
        /// <param name="bMessage">AES encrypted message.</param>
        /// <returns>Decrypted message.</returns>
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

        /// <summary>
        /// Encrypt messages using the key derived from the shared secret.
        /// </summary>
        /// <param name="bMessage">Plaintext message to encrypt.</param>
        /// <returns>AES encrypted message.</returns>
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
