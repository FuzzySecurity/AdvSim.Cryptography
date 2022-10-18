#if NETFRAMEWORK
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Windows
{
    /// <summary>
    /// Wrapper object to encrypt and decrypt data using
    /// the machine's DPAPI key.
    /// </summary>
    public class MachineDPAPIProvider : ICryptographicProvider
    {
        private byte[] _entropy = null;
        /// <summary>
        /// Create an object to encrypt and decrypt data with
        /// optional entropy. Default: No additional entropy.
        /// </summary>
        /// <param name="entropy">Optional entropy used to encrypt and decrypt data with.</param>
        public MachineDPAPIProvider(byte[] entropy = null)
        {
            _entropy = entropy;
        }
        /// <summary>
        /// Create an object to encrypt and decrypt data using additional entropy
        /// specified by the given string.
        /// </summary>
        /// <param name="entropySeed">String to derive optional entropy from.</param>
        /// <param name="length">Total number of bytes the entropy will be.</param>
        public MachineDPAPIProvider(string entropySeed, UInt32 length = 32)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(entropySeed),
                Encoding.UTF32.GetBytes(entropySeed).Reverse().ToArray(),
                10);
            _entropy = oRfc2898DeriveBytes.GetBytes((Int32)length);
        }

        /// <summary>
        /// Decrypt data previously encrypted using the machine's DPAPI encryption keys
        /// and optional entropy given on instantiation.
        /// </summary>
        /// <param name="bMessage">Message encrypted using the machine's DPAPI keys.</param>
        /// <returns>Decrypted message in bytes.</returns>
        public byte[] Decrypt(byte[] bMessage)
        {
            return ProtectedData.Unprotect(bMessage, _entropy, DataProtectionScope.LocalMachine);
        }

        /// <summary>
        /// Encrypts data using the machine's DPAPI encryption keys
        /// and optional entropy given on instantiation.
        /// </summary>
        /// <param name="bMessage">Message to be encrypted using the machine's DPAPI keys.</param>
        /// <returns>Encrypted message in bytes.</returns>
        public byte[] Encrypt(byte[] bMessage)
        {
            return ProtectedData.Protect(bMessage, _entropy, DataProtectionScope.LocalMachine);
        }
    }
}
#endif