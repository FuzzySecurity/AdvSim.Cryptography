using AdvSim.Cryptography.Asymmetric.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Asymmetric
{
    public class RSAProvider : ICryptographicProvider
    {
        public RSAParameters PublicKey { get; private set; }
        private RSAParameters PrivateKey;
        private RSACryptoServiceProvider _rsaProvider = null;
        public RSAProvider()
        {
            _rsaProvider = new RSACryptoServiceProvider(4096);
            PrivateKey = _rsaProvider.ExportParameters(true);
            PublicKey = _rsaProvider.ExportParameters(false);
        }

        public RSAProvider(byte[] Key, bool KeyIsPublicKey = true)
        {
            RSAParameters keyParams = RSAProvider.RSAParametersFromByteArray(Key);
            _rsaProvider = new RSACryptoServiceProvider();
            InitializeRSAProvider(keyParams, KeyIsPublicKey);
        }

        public RSAProvider(RSAParameters Key, bool KeyIsPublicKey = true)
        {
            _rsaProvider = new RSACryptoServiceProvider();
            InitializeRSAProvider(Key, KeyIsPublicKey);
        }

        private void InitializeRSAProvider(RSAParameters Key, bool KeyIsPublicKey = true)
        {
            if (KeyIsPublicKey)
            {
                this.PublicKey = Key;
            }
            else
            {
                this.PrivateKey = Key;
            }
            _rsaProvider.ImportParameters(Key);
        }

        public byte[] Decrypt(byte[] bMessage)
        {
            return _rsaProvider.Decrypt(bMessage, false);
        }

        public byte[] ExportPublicKey()
        {
            return PublicKey.GetBytes();
        }

        public byte[] Encrypt(byte[] bMessage)
        {
            return _rsaProvider.Encrypt(bMessage, false);
        }

        public static RSAParameters RSAParametersFromByteArray(byte[] Key)
        {
            using (StringReader sr = new StringReader(System.Text.Encoding.UTF8.GetString(Key)))
            {
                return (RSAParameters)new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters)).Deserialize(sr);
            }
        }
    }
}
