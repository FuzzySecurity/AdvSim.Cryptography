using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class RC4Provider : ICryptographicProvider
    {
        public byte[] Key { get; private set; }

        public RC4Provider(string Password)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(Password),
                Encoding.UTF32.GetBytes(Password).Reverse().ToArray(),
                10);
            Key = oRfc2898DeriveBytes.GetBytes(256);
        }

        public RC4Provider(byte[] Key)
        {
            this.Key = Key;
        }

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

        public byte[] Decrypt(byte[] bMessage)
        {
            return Encrypt(bMessage);
        }
    }
}
