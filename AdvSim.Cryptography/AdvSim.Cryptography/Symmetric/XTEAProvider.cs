using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    public class XTEAProvider : ICryptographicProvider
    {
        public byte[] Key { get; private set; }

        public XTEAProvider(string Password, int KeySize = 100)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(Password), Encoding.UTF32.GetBytes(Password).Reverse().ToArray(), 10);
            Key = oRfc2898DeriveBytes.GetBytes(KeySize);
        }

        public byte[] Decrypt(byte[] bMessage)
        {
            Byte[] keyBuffer = Key;
            UInt32[] blockBuffer = new UInt32[2];
            Byte[] buffer = new Byte[bMessage.Length];
            Array.Copy(bMessage, buffer, bMessage.Length);
            using (MemoryStream stream = new MemoryStream(buffer))
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    for (Int32 i = 0; i < buffer.Length; i += 8)
                    {
                        blockBuffer[0] = BitConverter.ToUInt32(buffer, i);
                        blockBuffer[1] = BitConverter.ToUInt32(buffer, i + 4);

                        UInt32 v0 = blockBuffer[0], v1 = blockBuffer[1], delta = 0x9E3779B9, sum = delta * 32;
                        for (UInt32 j = 0; j < 32; j++)
                        {
                            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + keyBuffer[(sum >> 11) & 3]);
                            sum -= delta;
                            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + keyBuffer[sum & 3]);
                        }
                        blockBuffer[0] = v0;
                        blockBuffer[1] = v1;

                        writer.Write(blockBuffer[0]);
                        writer.Write(blockBuffer[1]);
                    }
                }
            }
            // verify valid length
            UInt32 length = BitConverter.ToUInt32(buffer, 0);
            Byte[] result = new Byte[length];
            Array.Copy(buffer, 4, result, 0, length);
            return result;
        }

        public byte[] Encrypt(byte[] bMessage)
        {
            Byte[] keyBuffer = Key;
            UInt32[] blockBuffer = new UInt32[2];
            Byte[] result = new Byte[(bMessage.Length + 4 + 7) / 8 * 8];
            Byte[] lengthBuffer = BitConverter.GetBytes(bMessage.Length);
            Array.Copy(lengthBuffer, result, lengthBuffer.Length);
            Array.Copy(bMessage, 0, result, lengthBuffer.Length, bMessage.Length);
            using (MemoryStream stream = new MemoryStream(result))
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    for (Int32 i = 0; i < result.Length; i += 8)
                    {
                        blockBuffer[0] = BitConverter.ToUInt32(result, i);
                        blockBuffer[1] = BitConverter.ToUInt32(result, i + 4);

                        UInt32 v0 = blockBuffer[0], v1 = blockBuffer[1], sum = 0, delta = 0x9E3779B9;
                        for (UInt32 j = 0; j < 32; j++)
                        {
                            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + keyBuffer[sum & 3]);
                            sum += delta;
                            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + keyBuffer[(sum >> 11) & 3]);
                        }
                        blockBuffer[0] = v0;
                        blockBuffer[1] = v1;

                        writer.Write(blockBuffer[0]);
                        writer.Write(blockBuffer[1]);
                    }
                }
            }
            return result;
        }
    }
}
