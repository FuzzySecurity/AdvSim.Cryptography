using System;
using System.Collections.Generic;
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
        public byte[] Decrypt(byte[] bMessage)
        {
            return _rsaProvider.Decrypt(bMessage, false);
        }

        public byte[] Encrypt(byte[] bMessage)
        {
            return _rsaProvider.Encrypt(bMessage, false);
        }
    }
}
