using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    /// <summary>
    /// Wrapper around XOR encoding with a randomly generated
    /// key based on a given seed.
    /// </summary>
    public class MultiByteXORProvider : ICryptographicProvider
    {
        /// <summary>
        /// XOR Key used to encode and decode data
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// Generate a random XOR key based on a given seed (password).
        /// </summary>
        /// <param name="password">String to derive key bytes from.</param>
        /// <param name="keySize">Length of key used to XOR data.</param>
        public MultiByteXORProvider(string password, int keySize = 100)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(password), Encoding.UTF32.GetBytes(password).Reverse().ToArray(), 10);
            Key = oRfc2898DeriveBytes.GetBytes(keySize);
        }

        /// <summary>
        /// Instantiate an XOR encoder based on a given key.
        /// </summary>
        /// <param name="key">Key used to encode and decode data.</param>
        public MultiByteXORProvider(byte[] key)
        {
            Key = key;
        }

        /// <summary>
        /// XOR encode the provided byte array.
        /// </summary>
        /// <param name="bMessage">Plaintext message to encode.</param>
        /// <returns>XOR encoded message.</returns>
        public byte[] Decrypt(byte[] bMessage)
        {
            return Encrypt(bMessage);
        }

        /// <summary>
        /// Decode the provided XOR byte array.
        /// </summary>
        /// <param name="bMessage">XOR encoded data.</param>
        /// <returns>Decoded message.</returns>
        public byte[] Encrypt(byte[] bMessage)
        {
            Byte[] bCipher = new Byte[bMessage.Length];
            for (Int32 i = 0; i < bMessage.Length; i++)
            {
                bCipher[i] = (Byte)(bMessage[i] ^ Key[i % Key.Length]);
            }
            return bCipher;
        }
    }
}
