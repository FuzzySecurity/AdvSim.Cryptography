using AdvSim.Cryptography.Windows;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Principal;

namespace AdvSim.Cryptography.Test
{
    [TestClass]
    public class WindowsUnitTests
    {
        private const string _entropyString = "VeryRandomString";
        [TestMethod]
        public void TestMachineDPAPIProvider()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            // Requires high integrity
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                MachineDPAPIProvider provider = new MachineDPAPIProvider();
                ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
                tester.Test();
            }
        }

        [TestMethod]
        public void TestMachineDPAPIProviderWithSeed()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            // Requires high integrity
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                MachineDPAPIProvider provider = new MachineDPAPIProvider(_entropyString);
                ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
                tester.Test();
            }
        }

        [TestMethod]
        public void TestUserDPAPIProvider()
        {
            UserDPAPIProvider provider = new UserDPAPIProvider();
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }

        [TestMethod]
        public void TestUserDPAPIProviderWithSeed()
        {
            UserDPAPIProvider provider = new UserDPAPIProvider(_entropyString);
            ICryptographicProviderTest tester = new ICryptographicProviderTest(provider);
            tester.Test();
        }
    }
}
