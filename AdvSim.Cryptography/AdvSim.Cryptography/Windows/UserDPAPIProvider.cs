#if NETFRAMEWORK
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Windows
{
    public class UserDPAPIProvider : ICryptographicProvider
    {
        private byte[] _entropy = null;
        public UserDPAPIProvider(byte[] Entropy = null)
        {
            _entropy = Entropy;
        }

        public UserDPAPIProvider(string EntropySeed, UInt32 Length = 32)
        {
            Rfc2898DeriveBytes oRfc2898DeriveBytes = new Rfc2898DeriveBytes(
                Encoding.UTF32.GetBytes(EntropySeed),
                Encoding.UTF32.GetBytes(EntropySeed).Reverse().ToArray(),
                10);
            _entropy = oRfc2898DeriveBytes.GetBytes((Int32)Length);
        }
        public byte[] Decrypt(byte[] bMessage)
        {
            return ProtectedData.Unprotect(bMessage, _entropy, DataProtectionScope.CurrentUser);
        }

        public byte[] Encrypt(byte[] bMessage)
        {
            return ProtectedData.Protect(bMessage, _entropy, DataProtectionScope.CurrentUser);
        }
    }
}
#endif