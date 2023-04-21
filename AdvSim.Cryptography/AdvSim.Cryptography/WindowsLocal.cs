using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography
{
#if NETFRAMEWORK
    public class DPAPI
    {
        internal static String sDPAPIEntropy = String.Empty;

        // DPAPI Local Machine
        //---------------------

        /// <summary>
        /// Encrypt a byte array using local machine DPAPI key material.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] EncryptMachineDPAPI(Byte[] bData)
        {
            if (!String.IsNullOrEmpty(sDPAPIEntropy))
            {
                Byte[] bEntropy = hCrypto.GenerateEntropy(sDPAPIEntropy);
                return ProtectedData.Protect(bData, bEntropy, DataProtectionScope.LocalMachine);
            }
            
            return ProtectedData.Protect(bData, null, DataProtectionScope.LocalMachine);
        }

        /// <summary>
        /// Decrypt a byte array using local machine DPAPI key material.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] DecryptMachineDPAPI(Byte[] bData)
        {
            if (!String.IsNullOrEmpty(sDPAPIEntropy))
            {
                Byte[] bEntropy = hCrypto.GenerateEntropy(sDPAPIEntropy);
                return ProtectedData.Unprotect(bData, bEntropy, DataProtectionScope.LocalMachine);
            }
            
            return ProtectedData.Unprotect(bData, null, DataProtectionScope.LocalMachine);
        }

        // DPAPI Current User
        //---------------------

        /// <summary>
        /// Encrypt a byte array using current user DPAPI key material.
        /// </summary>
        /// <param name="bData">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] EncryptUserDPAPI(Byte[] bData)
        {
            if (!String.IsNullOrEmpty(sDPAPIEntropy))
            {
                Byte[] bEntropy = hCrypto.GenerateEntropy(sDPAPIEntropy);
                return ProtectedData.Protect(bData, bEntropy, DataProtectionScope.CurrentUser);
            }
            
            return ProtectedData.Protect(bData, null, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Decrypt a byte array using current user DPAPI key material.
        /// </summary>
        /// <param name="bData">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public Byte[] DecryptUserDPAPI(Byte[] bData)
        {
            if (!String.IsNullOrEmpty(sDPAPIEntropy))
            {
                Byte[] bEntropy = hCrypto.GenerateEntropy(sDPAPIEntropy);
                return ProtectedData.Unprotect(bData, bEntropy, DataProtectionScope.CurrentUser);
            }
            
            return ProtectedData.Unprotect(bData, null, DataProtectionScope.CurrentUser);
        }

        public DPAPI(String sEntropy = "")
        {
            if (!String.IsNullOrEmpty(sEntropy))
            {
                sDPAPIEntropy = sEntropy;
            }
        }
    }
#endif
}