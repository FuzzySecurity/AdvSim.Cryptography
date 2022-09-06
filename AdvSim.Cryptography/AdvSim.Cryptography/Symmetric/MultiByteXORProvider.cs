using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class MultiByteXORProvider : ICryptographicProvider
    {
        public byte[] Key { get; private set; }

        public MultiByteXORProvider(string Password, int KeySize = 100)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(Password), Encoding.UTF32.GetBytes(Password).Reverse().ToArray(), 10);
            Key = oRfc2898DeriveBytes.GetBytes(KeySize);
        }

        public byte[] Decrypt(byte[] bMessage)
        {
            return Encrypt(bMessage);
        }

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
