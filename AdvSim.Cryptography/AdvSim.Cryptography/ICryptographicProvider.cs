using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AdvSim.Cryptography
{
    public interface ICryptographicProvider
    {
        Byte[] Encrypt(byte[] bMessage);
        Byte[] Decrypt(byte[] bMessage);
    }
}
