using AdvSim.Cryptography.Asymmetric.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Asymmetric
{
    /// <summary>
    /// RSA encryption class used to encrypt and decrypt messages using RSA encryption.
    /// </summary>
    public class RSAProvider : ICryptographicProvider
    {
        /// <summary>
        /// The public key of this RSA instance. Useful in key exchange.
        /// </summary>
        public RSAParameters PublicKey { get; private set; }
        private RSAParameters _privateKey;
        private RSACryptoServiceProvider _rsaProvider = null;

        /// <summary>
        /// Instantiate a new RSAProvider object with a randomly generated
        /// initial key.
        /// </summary>
        public RSAProvider()
        {
            _rsaProvider = new RSACryptoServiceProvider(4096);
            _privateKey = _rsaProvider.ExportParameters(true);
            PublicKey = _rsaProvider.ExportParameters(false);
        }

        /// <summary>
        /// Create a new RSAProvider object using the given key material.
        /// </summary>
        /// <param name="key">Public or private key to instantiate this object with.</param>
        /// <param name="keyIsPublicKey">True if the value provided by key is a public key, otherwise false.</param>
        public RSAProvider(byte[] key, bool keyIsPublicKey = true)
        {
            RSAParameters keyParams = RSAProvider.RSAParametersFromByteArray(key);
            _rsaProvider = new RSACryptoServiceProvider();
            InitializeRSAProvider(keyParams, keyIsPublicKey);
        }
        /// <summary>
        /// Create a new RSAProvider object using the given key material.
        /// </summary>
        /// <param name="key">Public or private key to instantiate this object with.</param>
        /// <param name="keyIsPublicKey">True if the value provided by key is a public key, otherwise false.</param>
        public RSAProvider(RSAParameters key, bool keyIsPublicKey = true)
        {
            _rsaProvider = new RSACryptoServiceProvider();
            InitializeRSAProvider(key, keyIsPublicKey);
        }

        /// <summary>
        /// Instantiate instanced variables based on provided encryption material.
        /// </summary>
        /// <param name="key">Encryption key to initialize this object with.</param>
        /// <param name="keyIsPublicKey">Whether the value provided by key is a public or private key.</param>
        private void InitializeRSAProvider(RSAParameters key, bool keyIsPublicKey = true)
        {
            if (keyIsPublicKey)
            {
                this.PublicKey = key;
            }
            else
            {
                this._privateKey = key;
            }
            _rsaProvider.ImportParameters(key);
        }

        /// <summary>
        /// Decrypt an RSA encrypted message.
        /// </summary>
        /// <param name="bMessage">RSA encrypted message.</param>
        /// <returns>Plaintext message as a byte array.</returns>
        public byte[] Decrypt(byte[] bMessage)
        {
            return _rsaProvider.Decrypt(bMessage, false);
        }

        /// <summary>
        /// Encrypts a plaintext message using RSA encryption.
        /// </summary>
        /// <param name="bMessage">Plaintext message.</param>
        /// <returns>RSA encrypted message as a byte array.</returns>
        public byte[] Encrypt(byte[] bMessage)
        {
            return _rsaProvider.Encrypt(bMessage, false);
        }

        /// <summary>
        /// Derive an RSAParamters object based on the provided encryption key.
        /// </summary>
        /// <param name="key">Encryption key used to instantiate RSAParameters with.</param>
        /// <returns>RSAParameters managed object based off the given key.</returns>
        public static RSAParameters RSAParametersFromByteArray(byte[] key)
        {
            using (StringReader sr = new StringReader(System.Text.Encoding.UTF8.GetString(key)))
            {
                return (RSAParameters)new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Deserialize(sr);
            }
        }
    }
}
