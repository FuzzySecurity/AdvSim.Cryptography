using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AdvSim.Cryptography.Symmetric
{
    /// <summary>
    /// Enum defining supported symmetric encryption algorithms.
    /// </summary>
    public enum CryptographyType : UInt16
    {
        AES_CBC = 0x0001,
        TRIPLE_DES = 0x0002,
        RC4 = 0x0003,
        RC2 = 0x0004,
        MULTI_XOR = 0x0005,
        XTEA = 0x0006,
    }
}
