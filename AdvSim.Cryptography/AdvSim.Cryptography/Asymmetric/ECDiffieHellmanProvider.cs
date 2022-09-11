using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Asymmetric
{
#if NETFRAMEWORK || (NET6_0_OR_GREATER && WINDOWS)
    public class ECDiffieHellmanProvider : ICryptographicProvider
    {
        public Byte[] Key { get; private set; } = new byte[0];
        public Byte[] IV { get; private set; } = new byte[0];
        private ECDiffieHellmanCng _ecdh = null;

        private bool _sharedKeyDerived = false;

        public ECDiffieHellmanProvider()
        {
            _ecdh = new ECDiffieHellmanCng(521);
            _ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            _ecdh.HashAlgorithm = CngAlgorithm.Sha256;
        }

        public byte[] Decrypt(byte[] bMessage)
        {
            if (!_sharedKeyDerived)
            {
                throw new Exception("Cannot encrypt message until shared key is derived.");
            }
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;

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

        public byte[] Encrypt(byte[] bMessage)
        {
            if (!_sharedKeyDerived)
            {
                throw new Exception("Cannot encrypt message until shared key is derived.");
            }
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;

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

        public byte[] GetPublicKey()
        {
            return _ecdh.PublicKey.ToByteArray();
        }

        public void DeriveSharedKey(byte[] PublicKey)
        {
            if (_sharedKeyDerived)
            {
                throw new Exception("Shared key already negotiated.");
            }
            Byte[] sharedSecret = _ecdh.DeriveKeyMaterial(
                CngKey.Import(PublicKey, CngKeyBlobFormat.EccPublicBlob));

            Key = new Byte[16];
            IV = new Byte[16];

            Array.Copy(sharedSecret, 0, Key, 0, 16);
            Array.Copy(sharedSecret, 16, IV, 0, 16);
            _sharedKeyDerived = true;
        }

        public static void DeriveSharedKey(ref ECDiffieHellmanProvider Client, ref ECDiffieHellmanProvider Server)
        {
            byte[] clientPubKey = Client.GetPublicKey();
            byte[] serverPubKey = Server.GetPublicKey();

            Client.DeriveSharedKey(serverPubKey);
            Server.DeriveSharedKey(clientPubKey);
        }
    }
#endif
}
