#if NETFRAMEWORK

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography
{

    public class WindowsLocal
    {
        // String to entropy
        //============================

        /// <summary>
        /// Generate entropy from a string, optionally specify the amount of entropy returned.
        /// </summary>
        /// <param name="sEntropySeed">String seed used to generate pseudo-random entropy.</param>
        /// <param name="iLength">Amount of bytes to return, defaults to 32.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] generateEntropy(String sEntropySeed, UInt32 iLength = 32)
        {
            // Initialize derivation function
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-6.0
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(Encoding.UTF32.GetBytes(sEntropySeed), Encoding.UTF32.GetBytes(sEntropySeed).Reverse().ToArray(), 10);

            // Return pseudo-random array
            return oRfc2898DeriveBytes.GetBytes((Int32)iLength);
        }

        // DPAPI Local Machine
        //---------------------

        /// <summary>
        /// Encrypt a byte array using local machine DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toMachineDPAPI(Byte[] bMessage)
        {
            return ProtectedData.Protect(bMessage, null, DataProtectionScope.LocalMachine);
        }

        /// <summary>
        /// Encrypt a byte array using local machine DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <param name="bEntropy">Byte array which will be provide additional entropy.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toMachineDPAPI(Byte[] bMessage, Byte[] bEntropy)
        {
            return ProtectedData.Protect(bMessage, bEntropy, DataProtectionScope.LocalMachine);
        }

        /// <summary>
        /// Decrypt a byte array using local machine DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromMachineDPAPI(Byte[] bMessage)
        {
            return ProtectedData.Unprotect(bMessage, null, DataProtectionScope.LocalMachine);
        }

        /// <summary>
        /// Decrypt a byte array using local machine DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <param name="bEntropy">Byte array which was provided to add additional entropy.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromMachineDPAPI(Byte[] bMessage, Byte[] bEntropy)
        {
            return ProtectedData.Unprotect(bMessage, bEntropy, DataProtectionScope.LocalMachine);
        }

        // DPAPI Current User
        //---------------------

        /// <summary>
        /// Encrypt a byte array using current user DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toUserDPAPI(Byte[] bMessage)
        {
            return ProtectedData.Protect(bMessage, null, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Encrypt a byte array using current user DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be encrypted.</param>
        /// <param name="bEntropy">Byte array which will be provide additional entropy.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] toUserDPAPI(Byte[] bMessage, Byte[] bEntropy)
        {
            return ProtectedData.Protect(bMessage, bEntropy, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Decrypt a byte array using current user DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromUserDPAPI(Byte[] bMessage)
        {
            return ProtectedData.Unprotect(bMessage, null, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Decrypt a byte array using current user DPAPI key material.
        /// </summary>
        /// <param name="bMessage">Byte array which will be decrypted.</param>
        /// <param name="bEntropy">Byte array which was provided to add additional entropy.</param>
        /// <returns>Byte[]</returns>
        public static Byte[] fromUserDPAPI(Byte[] bMessage, Byte[] bEntropy)
        {
            return ProtectedData.Unprotect(bMessage, bEntropy, DataProtectionScope.CurrentUser);
        }
    }
}

#endif