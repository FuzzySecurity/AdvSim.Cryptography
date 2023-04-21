using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography
{
    public class hCrypto
    {
        /// <summary>
        /// ECDH key material containing Key/IV.
        /// </summary>
        internal class ECDH_KEY_MATERIAL
        {
            public Byte[] Key = null;
            public Byte[] IV = null;
        }

        /// <summary>
        /// RSA key material containing certificate public/private keypair.
        /// </summary>
        internal class RSA_KEY_MATERIAL
        {
            public RSAParameters PublicKey;
            public RSAParameters PrivateKey;
        }
        
        /// <summary>
        /// Generic key material object containing Key/IV.
        /// </summary>
        internal class KEY_MATERIAL
        {
            public Byte[] Key = null;
            public Byte[] IV = null;
        }
        
        /// <summary>
        /// Enum defining supported symmetric encryption algorithms.
        /// </summary>
        internal enum CryptographyType : UInt16
        {
            AES_CBC = 0x0001,
            TRIPLE_DES = 0x0002,
            RC4 = 0x0003,
            RC2 = 0x0004,
            MULTI_XOR = 0x0005,
            XTEA = 0x0006,
        }
        
        /// <summary>
        /// Generate KeyMaterial from a string. Output depends on the cryptography type selected.
        /// </summary>
        /// <param name="sPassword">String seed used to generate pseudo-random key material.</param>
        /// <param name="eType">Type of cryptographic key material to initialize.</param>
        /// <returns>Object</returns>
        internal static Object GenerateKeyMaterial(String sPassword, CryptographyType eType)
        {
            // Return object
            Object oKeyMaterial = null;

            // Initialize derivation function
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-6.0
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(sPassword), Encoding.UTF32.GetBytes(sPassword).Reverse().ToArray(), 20);

            switch (eType)
            {
                // Set output depending on algorithm
                case CryptographyType.AES_CBC:
                    oKeyMaterial = new KEY_MATERIAL
                    {
                        Key = oRfc2898DeriveBytes.GetBytes(32),
                        IV = oRfc2898DeriveBytes.GetBytes(16)
                    };
                    break;
                case CryptographyType.RC4:
                    oKeyMaterial = oRfc2898DeriveBytes.GetBytes(256);
                    break;
                case CryptographyType.MULTI_XOR:
                    oKeyMaterial = oRfc2898DeriveBytes.GetBytes(100);
                    break;
                case CryptographyType.TRIPLE_DES:
                    oKeyMaterial = new KEY_MATERIAL
                    {
                        Key = oRfc2898DeriveBytes.GetBytes(24),
                        IV = oRfc2898DeriveBytes.GetBytes(8)
                    };
                    break;
                case CryptographyType.RC2:
                    oKeyMaterial = new KEY_MATERIAL
                    {
                        Key = oRfc2898DeriveBytes.GetBytes(16),
                        IV = oRfc2898DeriveBytes.GetBytes(8)
                    };
                    break;
                case CryptographyType.XTEA:
                    oKeyMaterial = oRfc2898DeriveBytes.GetBytes(128);
                    break;
            }

            return oKeyMaterial;
        }
        
        /// <summary>
        /// Generate entropy from a string, optionally specify the amount of entropy returned.
        /// </summary>
        /// <param name="sEntropySeed">String seed used to generate pseudo-random entropy.</param>
        /// <param name="iLength">Amount of bytes to return, defaults to 32.</param>
        /// <returns>Byte[]</returns>
        internal static Byte[] GenerateEntropy(String sEntropySeed, UInt32 iLength = 32)
        {
            // Initialize derivation function
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-6.0
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(sEntropySeed), Encoding.UTF32.GetBytes(sEntropySeed).Reverse().ToArray(), 10);

            // Return pseudo-random array
            return oRfc2898DeriveBytes.GetBytes((Int32)iLength);
        }
        
        /// <summary>
        /// Internal function to convert a decimal string to a byte array.
        /// </summary>
        /// <param name="decimalString">Decimal string to convert to byte array</param>
        internal static Byte[] DecimalStringToByteArray(String decimalString)
        {
            Int32 byteCount = (Int32)Math.Ceiling(decimalString.Length * Math.Log10(10) / Math.Log10(256));
            Byte[] bytes = new Byte[byteCount];

            foreach (Char c in decimalString)
            {
                Int32 carry = c - '0';
                for (Int32 i = 0; i < bytes.Length; ++i)
                {
                    Int32 value = bytes[i] * 10 + carry;
                    bytes[i] = (Byte)(value % 256);
                    carry = value / 256;
                }
            }

            Array.Reverse(bytes);
            return bytes;
        }
    }
}