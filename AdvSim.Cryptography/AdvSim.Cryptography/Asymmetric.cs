using System;
using System.IO;
using System.Security.Cryptography;

namespace AdvSim.Cryptography
{
    public class Asymmetric
    {
        // Crypto Data types
        //============================

        /// <summary>
        /// ECDH key material containing Key/IV.
        /// </summary>
        public class ECDH_KEY_MAT
        {
            public Byte[] bKey;
            public Byte[] bIV;
        }

        /// <summary>
        /// RSA key material containing certificate public/private keypair.
        /// </summary>
        public class RSA_KEY_MAT
        {
            public RSAParameters oPublicKey;
            public RSAParameters oPrivateKey;
        }

        // Crypto functions
        //============================
        
#if NETFRAMEWORK || (NET6_0_OR_GREATER && WINDOWS)
        
        // ECDH
        //---------------------

        /// <summary>
        /// Generate a random ECDH public/private 521-bit keypair.
        /// </summary>
        /// <returns>RSA_KEY_MAT</returns>
        public static ECDiffieHellmanCng initializeECDH()
        {
            ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(521);
            ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecdh.HashAlgorithm = CngAlgorithm.Sha256;

            return ecdh;
        }

        /// <summary>
        /// Retrieve the ECDH public key from an initialized ECDiffieHellmanCng object.
        /// </summary>
        /// <param name="ecdh">Initialized ECDiffieHellmanCng object.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] getECDHPublicKey(ECDiffieHellmanCng ecdh)
        {
            return ecdh.PublicKey.ToByteArray();
        }

        /// <summary>
        /// Generate a shared secret Key/IV from an initialized ECDiffieHellmanCng object and a public key.
        /// </summary>
        /// <param name="ecdh">Initialized ECDiffieHellmanCng object.</param>
        /// <param name="publicKey">Public key byte array received during client exchange.</param>
        /// <returns>Byte[]</returns>
        public static ECDH_KEY_MAT deriveECDHSharedKeyMaterial(ECDiffieHellmanCng ecdh, Byte[] publicKey)
        {
            ECDH_KEY_MAT oKeyMat = new ECDH_KEY_MAT();
            
            // Note: You can only get 32-bytes of derived key material from this operation.
            Byte[] sharedSecret = ecdh.DeriveKeyMaterial(CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob));
            
            oKeyMat.bKey = new Byte[16];
            oKeyMat.bIV = new Byte[16];

            Array.Copy(sharedSecret, 0, oKeyMat.bKey, 0, 16);
            Array.Copy(sharedSecret, 16, oKeyMat.bIV, 0, 16);

            return oKeyMat;
        }

        /// <summary>
        /// Encrypt a byte array using AES with key material derived from an ECDH key exchange.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toECDH(ECDH_KEY_MAT oKeyMat, Byte[] bMessage)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.bKey;
                aes.IV = oKeyMat.bIV;

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
        /// Decrypt a byte array using AES with key material derived from an ECDH key exchange.
        /// </summary>
        /// <param name="oKeyMat">Key material used for the cryptographic operation.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromECDH(ECDH_KEY_MAT oKeyMat, Byte[] bMessage)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.bKey;
                aes.IV = oKeyMat.bIV;

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
        
#endif
        
        // RSA
        //---------------------

        /// <summary>
        /// Generate a random RSAParameters public/private 4096-bit keypair.
        /// </summary>
        /// <returns>RSA_KEY_MAT</returns>
        public static RSA_KEY_MAT initializeRSA()
        {
            RSA_KEY_MAT oRSA = new RSA_KEY_MAT();

            RSACryptoServiceProvider oRSAProvider = new RSACryptoServiceProvider(4096);
            oRSA.oPrivateKey = oRSAProvider.ExportParameters(true);
            oRSA.oPublicKey = oRSAProvider.ExportParameters(false);

            return oRSA;
        }

        /// <summary>
        /// Convert an RSAParameters public/private key object to a byte array.
        /// </summary>
        /// <param name="oKey">RSA key in an RSAParameters format.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] getArrayFromRSAParameters(RSAParameters oKey)
        {
            using (StringWriter sw = new StringWriter())
            {
                new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Serialize(sw, oKey);
                return System.Text.Encoding.UTF8.GetBytes(sw.ToString());
            }
        }

        /// <summary>
        /// Convert a byte array to an RSAParameters public/private key object.
        /// </summary>
        /// <param name="bKey">RSA key in a byte array format.</param>
        /// <returns>RSAParameters</returns>
        public static RSAParameters getRSAParametersFromArray(Byte[] bKey)
        {
            using (StringReader sr = new StringReader(System.Text.Encoding.UTF8.GetString(bKey)))
            {
                return (RSAParameters)new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Deserialize(sr);
            }
        }

        /// <summary>
        /// Encrypt a byte array using an RSA certificate public key.
        /// </summary>
        /// <param name="oPublicKey">RSA public key in an RSAParameters format.</param>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toRSA(RSAParameters oPublicKey, Byte[] bMessage)
        {
            RSACryptoServiceProvider oRSAProvider = new RSACryptoServiceProvider();
            oRSAProvider.ImportParameters(oPublicKey);

            return oRSAProvider.Encrypt(bMessage, false);
        }

        /// <summary>
        /// Decrypt a byte array using an RSA certificate private key.
        /// </summary>
        /// <param name="oPrivateKey">RSA private key in an RSAParameters format.</param>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromRSA(RSAParameters oPrivateKey, Byte[] bMessage)
        {
            RSACryptoServiceProvider oRSAProvider = new RSACryptoServiceProvider();
            oRSAProvider.ImportParameters(oPrivateKey);

            return oRSAProvider.Decrypt(bMessage, false);
        }
    }
}