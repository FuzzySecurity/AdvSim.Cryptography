using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using AdvSim.Cryptography;

namespace AdvSim.Cryptography.Test
{
    public class ICryptographicProviderTest
    {
        private const string _message = "This is my secret message!";
        private byte[] _bMessage = System.Text.Encoding.UTF8.GetBytes(_message);
        private ICryptographicProvider _provider;
        public ICryptographicProviderTest(ICryptographicProvider provider)
        {
            _provider = provider;
        }
        public void Test()
        {
            byte[] result = _provider.Encrypt(_bMessage);
            Assert.AreNotEqual(result, _bMessage, "Encrypt method returned unencrypted result.");
            Assert.AreNotEqual(result.Length, 0, "Encrypt method returned empty array.");

            byte[] result2 = _provider.Decrypt(result);
            string final = System.Text.Encoding.UTF8.GetString(result2);
            Assert.AreEqual(_message, final, "Decryption did not match given input.");
        }
    }
}
