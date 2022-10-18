using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class RC4Provider : ICryptographicProvider
    {
        /// <summary>
        /// RC4 encryption key used to encrypt and decrypt data.
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// Derive RC4 encryption material based on a shared secret.
        /// </summary>
        /// <param name="password">Shared secret to derive RC4 encryption key from.</param>
        public RC4Provider(string password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(password),
                Encoding.UTF32.GetBytes(password).Reverse().ToArray(),
                10);
            Key = oRfc2898DeriveBytes.GetBytes(256);
        }

        /// <summary>
        /// Set the encryption key of the RC4 cryptor to the given key.
        /// </summary>
        /// <param name="key">Encryption key used in RC4 encryption.</param>
        public RC4Provider(byte[] key)
        {
            this.Key = key;
        }

        /// <summary>
        /// Encrypt a plaintext message using RC4 encryption.
        /// </summary>
        /// <param name="bMessage">Plaintext message to encrypt.</param>
        /// <returns>RC4 encrypted byte array.</returns>
        public byte[] Encrypt(byte[] bMessage)
        {
            Int32 a, i, j;
            Int32 tmp;

            Int32[] key = new Int32[256];
            Int32[] box = new Int32[256];
            Byte[] cipher = new Byte[bMessage.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = Key[i % Key.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < bMessage.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                Int32 k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (Byte)(bMessage[i] ^ k);
            }
            return cipher;
        }

        /// <summary>
        /// Decrypt a plaintext message using RC4 decryption.
        /// </summary>
        /// <param name="bMessage">RC4 encrypted message.</param>
        /// <returns>Plaintext message as a byte array.</returns>
        public byte[] Decrypt(byte[] bMessage)
        {
            return Encrypt(bMessage);
        }
    }
}
