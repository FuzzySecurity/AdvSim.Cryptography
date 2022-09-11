using AdvSim.Cryptography.Symmetric;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace AdvSim.Cryptography.Test
{
    [TestClass]
    public class SymmetricUnitTests
    {
        private const string _password = "MyVerySecretPassword";
        [TestMethod]
        public void TestAESProvider()
        {
            AESProvider provider = new AESProvider(_password);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }

        [TestMethod]
        public void TestMultiByteXORProvider()
        {
            MultiByteXORProvider provider = new MultiByteXORProvider(_password);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }

        [TestMethod]
        public void TestRC2Provider()
        {
            RC2Provider provider = new RC2Provider(_password);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }

        [TestMethod]
        public void TestRC4Provider()
        {
            RC4Provider provider = new RC4Provider(_password);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }

        [TestMethod]
        public void TestXTEAProvider()
        {
            XTEAProvider provider = new XTEAProvider(_password);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }

        [TestMethod]
        public void TestTripleDESProvider()
        {
            TripleDESProvider provider = new TripleDESProvider(_password);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }
    }
}
