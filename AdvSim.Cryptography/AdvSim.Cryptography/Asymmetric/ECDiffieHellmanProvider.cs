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
        public Byte[] Key { get; private set; }
        public Byte[] IV { get; private set; }
        private ECDiffieHellmanCng _ecdh = null;

        public ECDiffieHellmanProvider()
        {
            _ecdh = new ECDiffieHellmanCng(521);
            _ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            _ecdh.HashAlgorithm = CngAlgorithm.Sha256;

            Byte[] sharedSecret = _ecdh.DeriveKeyMaterial(
                CngKey.Import(_ecdh.PublicKey.ToByteArray(), CngKeyBlobFormat.EccPublicBlob));

            Key = new Byte[16];
            IV = new Byte[16];

            Array.Copy(sharedSecret, 0, Key, 0, 16);
            Array.Copy(sharedSecret, 16, IV, 0, 16);
        }

        public byte[] Decrypt(byte[] bMessage)
        {
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
    }
#endif
}
