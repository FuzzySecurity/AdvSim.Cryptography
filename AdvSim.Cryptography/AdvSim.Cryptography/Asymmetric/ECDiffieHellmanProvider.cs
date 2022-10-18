using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Asymmetric
{
#if NETFRAMEWORK || (NET6_0_OR_GREATER && WINDOWS)
    /// <summary>
    /// Elliptic Curve Diffie Helman cryptographic object to encrypt and decrypt data.
    /// </summary>
    public class ECDiffieHellmanProvider : ICryptographicProvider
    {
        public Byte[] Key { get; private set; } = new byte[0];
        private Byte[] _iv = new byte[0];
        private ECDiffieHellmanCng _ecdh = null;

        /// <summary>
        /// ECDH requires a key exchange process to derive a shared secret to encrypt
        /// and decrypt data with. If this key exchange has not been performed,
        /// then subsequent calls to encrypt/decrypt will fail.
        /// </summary>
        private bool _sharedKeyDerived = false;

        /// <summary>
        /// Create a new ECDH object that will use Sha256 hashing to derive an encryption key.
        /// </summary>
        public ECDiffieHellmanProvider()
        {
            _ecdh = new ECDiffieHellmanCng(521);
            _ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            _ecdh.HashAlgorithm = CngAlgorithm.Sha256;
        }

        /// <summary>
        /// Decrypt a message previously encrypted with the derived shared key of
        /// this ECDH instance. If no shared key has been derived on this object,
        /// this function will throw an exception.
        /// </summary>
        /// <param name="bMessage">ECDH encrypted message.</param>
        /// <returns>Plaintext message.</returns>
        public byte[] Decrypt(byte[] bMessage)
        {
            if (!_sharedKeyDerived)
            {
                throw new Exception("Cannot encrypt message until shared key is derived.");
            }
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = _iv;

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

        /// <summary>
        /// Encrypt a plaintext message using the derived shared key of
        /// this ECDH instance. If no shared key has been derived on this object,
        /// this function will throw an exception.
        /// </summary>
        /// <param name="bMessage">Plaintext message to encrypt using ECDH.</param>
        /// <returns>ECDH encrypted message as a byte array.</returns>
        public byte[] Encrypt(byte[] bMessage)
        {
            if (!_sharedKeyDerived)
            {
                throw new Exception("Cannot encrypt message until shared key is derived.");
            }
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = _iv;

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
        /// Thin wrapper to get the public key of the ECDH encryption.
        /// </summary>
        /// <returns></returns>
        public byte[] GetPublicKey()
        {
            return _ecdh.PublicKey.ToByteArray();
        }


        /// <summary>
        /// Derive a shared secret based on another provider's public key. This function
        /// call must be called once the other ECDH client provides their public key used
        /// in encryption.
        /// </summary>
        /// <param name="publicKey">Public key of another client's encryption key.</param>
        public void DeriveSharedKey(byte[] publicKey)
        {
            if (_sharedKeyDerived)
            {
                throw new Exception("Shared key already negotiated.");
            }
            Byte[] sharedSecret = _ecdh.DeriveKeyMaterial(
                CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob));

            Key = new Byte[16];
            _iv = new Byte[16];

            Array.Copy(sharedSecret, 0, Key, 0, 16);
            Array.Copy(sharedSecret, 16, _iv, 0, 16);
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
