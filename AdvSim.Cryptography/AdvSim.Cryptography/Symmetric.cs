using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography
{
    public class Symmetric
    {
        // Crypto Data types
        //============================

        /// <summary>
        /// Enum defining supported symmetric encryption algorithms.
        /// </summary>
        public enum CryptographyType : UInt16
        {
            AES_CBC = 0x0001,
            TRIPLE_DES = 0x0002,
            RC4 = 0x0003,
            RC2 = 0x0004,
            MULTI_XOR = 0x0005,
            XTEA = 0x0006,
        }

        /// <summary>
        /// Generic key material object containing Key/IV.
        /// </summary>
        public class GENERIC_KEY_MAT
        {
            public Byte[] bKey;
            public Byte[] bIV;
        }

        // String to key material
        //============================

        /// <summary>
        /// Generate oKeyMaterial from a string. Output depends on the cryptography type selected.
        /// </summary>
        /// <param name="sPassword">String seed used to generate pseudo-random key material.</param>
        /// <param name="eType">Type of cryptographic key material to initialize.</param>
        /// <returns>Object</returns>
        public static Object generateKeyMaterial(String sPassword, CryptographyType eType)
        {
            // Return object
            Object oKeyMaterial = null;

            // Initialize derivation function
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-6.0
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(sPassword), Encoding.UTF32.GetBytes(sPassword).Reverse().ToArray(), 10);

            switch (eType)
            {
                // Set output depending on algorithm
                case CryptographyType.AES_CBC:
                    oKeyMaterial = new GENERIC_KEY_MAT
                    {
                        bKey = oRfc2898DeriveBytes.GetBytes(32),
                        bIV = oRfc2898DeriveBytes.GetBytes(16)
                    };
                    break;
                case CryptographyType.RC4:
                    oKeyMaterial = oRfc2898DeriveBytes.GetBytes(256);
                    break;
                case CryptographyType.MULTI_XOR:
                    oKeyMaterial = oRfc2898DeriveBytes.GetBytes(100);
                    break;
                case CryptographyType.TRIPLE_DES:
                    oKeyMaterial = new GENERIC_KEY_MAT
                    {
                        bKey = oRfc2898DeriveBytes.GetBytes(24),
                        bIV = oRfc2898DeriveBytes.GetBytes(8)
                    };
                    break;
                case CryptographyType.RC2:
                    oKeyMaterial = new GENERIC_KEY_MAT
                    {
                        bKey = oRfc2898DeriveBytes.GetBytes(16),
                        bIV = oRfc2898DeriveBytes.GetBytes(8)
                    };
                    break;
                case CryptographyType.XTEA:
                    oKeyMaterial = oRfc2898DeriveBytes.GetBytes(128);
                    break;
            }

            return oKeyMaterial;
        }

        // Crypto functions
        //============================

        // AES Managed
        //---------------------

        /// <summary>
        /// Encrypt byte array to AES byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toAES(Object oKeyMat, Byte[] bMessage)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = (oKeyMat as GENERIC_KEY_MAT).bKey;
                aes.IV = (oKeyMat as GENERIC_KEY_MAT).bIV;

                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);
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

        /// <summary>
        /// Decrypt byte array from AES byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromAES(Object oKeyMat, Byte[] bMessage)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = (oKeyMat as GENERIC_KEY_MAT).bKey;
                aes.IV = (oKeyMat as GENERIC_KEY_MAT).bIV;

                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);
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
        }

        // Triple DES
        //---------------------

        /// <summary>
        /// Encrypt byte array to Triple DES byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toTripleDES(Object oKeyMat, Byte[] bMessage)
        {
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = (oKeyMat as GENERIC_KEY_MAT).bKey;
                tdes.IV = (oKeyMat as GENERIC_KEY_MAT).bIV;

                ICryptoTransform enc = tdes.CreateEncryptor(tdes.Key, tdes.IV);
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

        /// <summary>
        /// Decrypt byte array from Triple DES byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromTripleDES(Object oKeyMat, Byte[] bMessage)
        {
            using (TripleDES tdes = TripleDES.Create())
            {
                tdes.Key = (oKeyMat as GENERIC_KEY_MAT).bKey;
                tdes.IV = (oKeyMat as GENERIC_KEY_MAT).bIV;

                ICryptoTransform dec = tdes.CreateDecryptor(tdes.Key, tdes.IV);
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
        }

        // RC4
        //---------------------

        /// <summary>
        /// Encrypt byte array to RC4 byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toRC4(Object oKeyMat, Byte[] bMessage)
        {
            Int32 a, i, j;
            Int32 tmp;

            Int32[] key = new Int32[256];
            Int32[] box = new Int32[256];
            Byte[] cipher = new Byte[bMessage.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = (oKeyMat as Byte[])[i % (oKeyMat as Byte[]).Length];
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
        /// Decrypt byte array from RC4 byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromRC4(Object oKeyMat, Byte[] bMessage)
        {
            return toRC4(oKeyMat, bMessage);
        }

        // RC2
        //---------------------

        /// <summary>
        /// Encrypt byte array to RC2 byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toRC2(Object oKeyMat, Byte[] bMessage)
        {
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Key = (oKeyMat as GENERIC_KEY_MAT).bKey;
                rc2.IV = (oKeyMat as GENERIC_KEY_MAT).bIV;

                ICryptoTransform enc = rc2.CreateEncryptor(rc2.Key, rc2.IV);
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

        /// <summary>
        /// Decrypt byte array from RC2 byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromRC2(Object oKeyMat, Byte[] bMessage)
        {
            using (RC2 rc2 = RC2.Create())
            {
                rc2.Key = (oKeyMat as GENERIC_KEY_MAT).bKey;
                rc2.IV = (oKeyMat as GENERIC_KEY_MAT).bIV;

                ICryptoTransform dec = rc2.CreateDecryptor(rc2.Key, rc2.IV);
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
        }

        // Multi XOR
        //---------------------

        /// <summary>
        /// Encrypt byte array using 100-byte XOR key.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toMultiXOR(Object oKeyMat, Byte[] bMessage)
        {
            Byte[] bKey = (oKeyMat as Byte[]);
            Byte[] bCipher = new Byte[bMessage.Length];
            for (Int32 i = 0; i < bMessage.Length; i++)
            {
                bCipher[i] = (Byte)(bMessage[i] ^ bKey[i % bKey.Length]);
            }
            return bCipher;
        }

        /// <summary>
        /// Decrypt byte array using 100-byte XOR key.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromMultiXOR(Object oKeyMat, Byte[] bMessage)
        {
            return toMultiXOR(oKeyMat, bMessage);
        }

        // XTEA
        //---------------------

        /// <summary>
        /// Encrypt byte array to XTEA byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toXTEA(Object oKeyMat, Byte[] bMessage)
        {
            Byte[] keyBuffer = (oKeyMat as Byte[]);
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

        /// <summary>
        /// Decrypt byte array from XTEA byte array.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromXTEA(Object oKeyMat, Byte[] bMessage)
        {
            Byte[] keyBuffer = (oKeyMat as Byte[]);
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
    }
}