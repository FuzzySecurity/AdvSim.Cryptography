using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace AdvSim.Cryptography
{
    public class RSA
    {
        internal static hCrypto.RSA_KEY_MATERIAL KeyMaterial = null;
        
        /// <summary>
        /// Convert an RSAParameters public key object to a byte array.
        /// </summary>
        /// <returns>Byte[]</returns>
        public Byte[] GetPublicKeyArray()
        {
            using (StringWriter sw = new StringWriter())
            {
                new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Serialize(sw, KeyMaterial.PublicKey);
                return System.Text.Encoding.UTF8.GetBytes(sw.ToString());
            }
        }
        
        /// <summary>
        /// Convert a byte array to an RSAParameters key object.
        /// </summary>
        /// <param name="bKey">RSA key in a byte array format.</param>
        /// <returns>RSAParameters</returns>
        internal RSAParameters ConvertArrayToRSAParameters(Byte[] bKeyObject)
        {
            using (StringReader sr = new StringReader(System.Text.Encoding.UTF8.GetString(bKeyObject)))
            {
                return (RSAParameters)new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Deserialize(sr);
            }
        }
        
        /// <summary>
        /// Encrypt a byte array using an RSA certificate public key.
        /// </summary>
        /// <param name="bPublicKey">RSA public key.</param>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bPublicKey, Byte[] bData)
        {
            RSACryptoServiceProvider oRSAProvider = new RSACryptoServiceProvider();
            RSAParameters oPublicKey = ConvertArrayToRSAParameters(bPublicKey);
            oRSAProvider.ImportParameters(oPublicKey);

            return oRSAProvider.Encrypt(bData, false);
        }

        /// <summary>
        /// Decrypt a byte array using an RSA certificate private key.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            RSACryptoServiceProvider oRSAProvider = new RSACryptoServiceProvider();
            oRSAProvider.ImportParameters(KeyMaterial.PrivateKey);

            return oRSAProvider.Decrypt(bData, false);
        }
        
        public RSA()
        {
            KeyMaterial = new hCrypto.RSA_KEY_MATERIAL();
            RSACryptoServiceProvider oRSAProvider = new RSACryptoServiceProvider(4096);
            KeyMaterial.PrivateKey = oRSAProvider.ExportParameters(true);
            KeyMaterial.PublicKey = oRSAProvider.ExportParameters(false);
        }
    }

    public class ECDH
    {
#if NET47_OR_GREATER || NETSTANDARD2_1_OR_GREATER || NET6_0_OR_GREATER // NET47_OR_GREATER
        internal static ECDiffieHellman ecdh = null;
        internal static ECCurveType Curve;
        internal static hCrypto.ECDH_KEY_MATERIAL oKeyMat = new hCrypto.ECDH_KEY_MATERIAL();

        /// <summary>
        /// ECCurveType enum defining supported elliptic curve cryptography algorithms.
        /// </summary>
        public enum ECCurveType
        {
            brainpoolP160r1,
            brainpoolP160t1,
            brainpoolP192r1,
            brainpoolP192t1,
            brainpoolP224r1,
            brainpoolP224t1,
            brainpoolP256r1,
            brainpoolP256t1,
            brainpoolP320r1,
            brainpoolP320t1,
            brainpoolP384r1,
            brainpoolP384t1,
            brainpoolP512r1,
            brainpoolP512t1,
            nistP256,
            nistP384,
            nistP521
        }

        internal ECDiffieHellman ImportPublicParameters(Byte[] bPublicKey)
        {
            String sPublicKey = Encoding.UTF8.GetString(bPublicKey);
            String[] parts = sPublicKey.Split(';');
            Byte[] xBytes = Convert.FromBase64String(parts[0]);
            Byte[] yBytes = Convert.FromBase64String(parts[1]);
        
            ECParameters ecParameters = new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName(Enum.GetName(typeof(ECCurveType), Curve)),
                Q = new ECPoint { X = xBytes, Y = yBytes }
            };
    
            ECDiffieHellman ecdhParam = ECDiffieHellman.Create();
            ecdhParam.ImportParameters(ecParameters);
    
            return ecdhParam;
        }

        /// <summary>
        /// Retrieve the ECDH public key from an initialized ECDiffieHellman object.
        /// </summary>
        /// <returns>Byte[]</returns>
        public Byte[] GetPublicKeyArray()
        {
            ECParameters ecParameters = ecdh.ExportParameters(false);
            Byte[] xBytes = ecParameters.Q.X;
            Byte[] yBytes = ecParameters.Q.Y;
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(xBytes) + ";" + Convert.ToBase64String(yBytes));
        }

        /// <summary>
        /// Generate a shared secret Key/IV from an initialized ECDiffieHellmanCng object and a public key.
        /// </summary>
        /// <param name="publicKey">Public key byte array received during client exchange.</param>
        public void DeriveSharedKey(Byte[] publicKey)
        {
            // Convert public key string to ECDiffieHellman public key
            ECDiffieHellman ecdhPublicKey = ImportPublicParameters(publicKey);
            
            // Derive shared secret
            Byte[] sharedSecret = ecdh.DeriveKeyMaterial(ecdhPublicKey.PublicKey);
            oKeyMat.Key = new Byte[16];
            oKeyMat.IV = new Byte[16];
            
            Array.Copy(sharedSecret, 0, oKeyMat.Key, 0, 16);
            Array.Copy(sharedSecret, 16, oKeyMat.IV, 0, 16);
        }

        /// <summary>
        /// Encrypt a byte array using AES with key material derived from an ECDH key exchange.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.Key;
                aes.IV = oKeyMat.IV;

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
        /// Decrypt a byte array using AES with key material derived from an ECDH key exchange.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.Key;
                aes.IV = oKeyMat.IV;

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
        
        public ECDH(ECCurveType curveType)
        {
            Curve = curveType;
            ecdh = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName(Enum.GetName(typeof(ECCurveType), curveType)));
        }
#elif NETFRAMEWORK
        internal static ECDiffieHellmanCng ecdhCng = null;
        internal static hCrypto.ECDH_KEY_MATERIAL oKeyMat = new hCrypto.ECDH_KEY_MATERIAL();

        /// <summary>
        /// Retrieve the ECDH public key from an initialized ECDiffieHellmanCng object.
        /// </summary>
        /// <returns>Byte[]</returns>
        public Byte[] GetPublicKeyArray()
        {
            return ecdhCng.PublicKey.ToByteArray();
        }
        
        /// <summary>
        /// Generate a shared secret Key/IV from an initialized ECDiffieHellmanCng object and a public key.
        /// </summary>
        /// <param name="publicKey">Public key byte array received during client exchange.</param>
        public void DeriveSharedKey(Byte[] publicKey)
        {
            Byte[] sharedSecret = ecdhCng.DeriveKeyMaterial(CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob));
            
            oKeyMat.Key = new Byte[16];
            oKeyMat.IV = new Byte[16];
            Array.Copy(sharedSecret, 0, oKeyMat.Key, 0, 16);
            Array.Copy(sharedSecret, 16, oKeyMat.IV, 0, 16);
        }

        /// <summary>
        /// Encrypt a byte array using AES with key material derived from an ECDH key exchange.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Encrypt(Byte[] bData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.Key;
                aes.IV = oKeyMat.IV;

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
        /// Decrypt a byte array using AES with key material derived from an ECDH key exchange.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] Decrypt(Byte[] bData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = oKeyMat.Key;
                aes.IV = oKeyMat.IV;

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
        
        public ECDH()
        {
            ecdhCng = new ECDiffieHellmanCng(256);
            ecdhCng.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecdhCng.HashAlgorithm = CngAlgorithm.Sha256;
        }
#endif
    }
}