using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AdvSim.Cryptography
{
    /// <summary>
    /// Interface defining a set of methods to encrypt and decrypt
    /// a byte array.
    /// </summary>
    public interface ICryptographicProvider
    {
        /// <summary>
        /// Given a byte array, encrypt it such that the implementer of this
        /// interface can call Decrypt on the resultant array to retrieve the
        /// original array.
        /// </summary>
        /// <param name="bMessage">Byte array to encrypt.</param>
        /// <returns>Encrypted byte array.</returns>
        Byte[] Encrypt(byte[] bMessage);
        /// <summary>
        /// Given an encrypted byte array, return the decrypted contents.
        /// </summary>
        /// <param name="bMessage">Byte array that has been encrypted, either from
        /// a previous call to Encrypt or otherwise.
        /// </param>
        /// <returns>Plaintext message within the encrypted array.</returns>
        Byte[] Decrypt(byte[] bMessage);
    }
}
