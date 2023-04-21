using System;
using System.IO;
using System.Security.Cryptography;

namespace AdvSim.Cryptography
{
    public class AES
    {
        internal static Object KeyMaterial = null;
        
        /// <summary>
        /// Encrypt byte array to AES byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = (KeyMaterial as hCrypto.KEY_MATERIAL).Key;
                aes.IV = (KeyMaterial as hCrypto.KEY_MATERIAL).IV;

                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bData);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        /// <summary>
        /// Decrypt byte array from AES byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = (KeyMaterial as hCrypto.KEY_MATERIAL).Key;
                aes.IV = (KeyMaterial as hCrypto.KEY_MATERIAL).IV;

                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bData);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        public AES(String sPassword)
        {
            KeyMaterial = hCrypto.GenerateKeyMaterial(sPassword, hCrypto.CryptographyType.AES_CBC);
        }
    }
    
    public class TripleDES
    {
        internal static Object KeyMaterial = null;
        
        /// <summary>
        /// Encrypt byte array to Triple DES byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            using (System.Security.Cryptography.TripleDES tdes = System.Security.Cryptography.TripleDES.Create())
            {
                tdes.Key = (KeyMaterial as hCrypto.KEY_MATERIAL).Key;
                tdes.IV = (KeyMaterial as hCrypto.KEY_MATERIAL).IV;
                
                ICryptoTransform enc = tdes.CreateEncryptor(tdes.Key, tdes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bData);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        /// <summary>
        /// Decrypt byte array from Triple DES byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            using (System.Security.Cryptography.TripleDES tdes = System.Security.Cryptography.TripleDES.Create())
            {
                tdes.Key = (KeyMaterial as hCrypto.KEY_MATERIAL).Key;
                tdes.IV = (KeyMaterial as hCrypto.KEY_MATERIAL).IV;
                
                ICryptoTransform dec = tdes.CreateDecryptor(tdes.Key, tdes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bData);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        public TripleDES(String sPassword)
        {
            KeyMaterial = hCrypto.GenerateKeyMaterial(sPassword, hCrypto.CryptographyType.TRIPLE_DES);
        }
    }

    public class RC4
    {
        internal static Object KeyMaterial = null;
        
        /// <summary>
        /// Encrypt byte array to RC4 byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            Int32 a, i, j;
            Int32 tmp;

            Int32[] key = new Int32[256];
            Int32[] box = new Int32[256];
            Byte[] cipher = new Byte[bData.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = (KeyMaterial as Byte[])[i % (KeyMaterial as Byte[]).Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < bData.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                Int32 k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (Byte)(bData[i] ^ k);
            }
            return cipher;
        }

        /// <summary>
        /// Decrypt byte array from RC4 byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            return Encrypt(bData);
        }
        
        public RC4(String sPassword)
        {
            KeyMaterial = hCrypto.GenerateKeyMaterial(sPassword, hCrypto.CryptographyType.RC4);
        }
    }
    
    public class RC2
    {
        internal static Object KeyMaterial = null;
        
        /// <summary>
        /// Encrypt byte array to RC2 byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            using (System.Security.Cryptography.RC2 rc2 = System.Security.Cryptography.RC2.Create())
            {
                rc2.Key = (KeyMaterial as hCrypto.KEY_MATERIAL).Key;
                rc2.IV = (KeyMaterial as hCrypto.KEY_MATERIAL).IV;

                ICryptoTransform enc = rc2.CreateEncryptor(rc2.Key, rc2.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bData);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt byte array from RC2 byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            using (System.Security.Cryptography.RC2 rc2 = System.Security.Cryptography.RC2.Create())
            {
                rc2.Key = (KeyMaterial as hCrypto.KEY_MATERIAL).Key;
                rc2.IV = (KeyMaterial as hCrypto.KEY_MATERIAL).IV;

                ICryptoTransform dec = rc2.CreateDecryptor(rc2.Key, rc2.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter sw = new BinaryWriter(cs))
                        {
                            sw.Write(bData);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }
        
        public RC2(String sPassword)
        {
            KeyMaterial = hCrypto.GenerateKeyMaterial(sPassword, hCrypto.CryptographyType.RC2);
        }
    }
    
    public class MultiXOR
    {
        internal static Object KeyMaterial = null;
        
        /// <summary>
        /// Encrypt byte array using 100-byte XOR key.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            Byte[] bKey = (KeyMaterial as Byte[]);
            Byte[] bCipher = new Byte[bData.Length];
            for (Int32 i = 0; i < bData.Length; i++)
            {
                bCipher[i] = (Byte)(bData[i] ^ bKey[i % bKey.Length]);
            }
            return bCipher;
        }

        /// <summary>
        /// Decrypt byte array using 100-byte XOR key.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            return Encrypt(bData);
        }
        
        public MultiXOR(String sPassword)
        {
            KeyMaterial = hCrypto.GenerateKeyMaterial(sPassword, hCrypto.CryptographyType.MULTI_XOR);
        }
    }
    
    public class XTEA
    {
        internal static Object KeyMaterial = null;
        
        /// <summary>
        /// Encrypt byte array to XTEA byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            Byte[] keyBuffer = (KeyMaterial as Byte[]);
            UInt32[] blockBuffer = new UInt32[2];
            Byte[] result = new Byte[(bData.Length + 4 + 7) / 8 * 8];
            Byte[] lengthBuffer = BitConverter.GetBytes(bData.Length);
            Array.Copy(lengthBuffer, result, lengthBuffer.Length);
            Array.Copy(bData, 0, result, lengthBuffer.Length, bData.Length);
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

        /// <summary>
        /// Decrypt byte array from XTEA byte array.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            Byte[] keyBuffer = (KeyMaterial as Byte[]);
            UInt32[] blockBuffer = new UInt32[2];
            Byte[] buffer = new Byte[bData.Length];
            Array.Copy(bData, buffer, bData.Length);
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
        
        public XTEA(String sPassword)
        {
            KeyMaterial = hCrypto.GenerateKeyMaterial(sPassword, hCrypto.CryptographyType.XTEA);
        }
    }
}