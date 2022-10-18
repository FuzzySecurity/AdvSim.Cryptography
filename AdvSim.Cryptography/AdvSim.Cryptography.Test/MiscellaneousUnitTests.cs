using AdvSim.Cryptography.Miscellaneous;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace AdvSim.Cryptography.Test
{
    [TestClass]
    public class MiscellaneousUnitTests
    {
        private const string _seed = "MyVeryCoolSeedValue";
        [TestMethod]
        public void TestTOTP()
        {
            TOTP provider = new TOTP(_seed);
            TOTP provider2 = new TOTP(_seed);
            TOTP invalidProvider = new TOTP("Wrong Seed");

            Assert.AreEqual(provider.Code, provider2.Code, "TOTP Generated two different codes for the same seed.");
            Assert.AreEqual(provider.LastCode, provider2.LastCode, "TOTP Generated two different last codes for the same seed.");
            Assert.IsFalse(provider.Validate(provider2.LastCode));
            Assert.IsTrue(provider.Validate(provider2.LastCode, true));
            Assert.IsTrue(provider.Validate(provider.Code));

            Assert.AreNotEqual(provider.Code, invalidProvider.Code, "Same code generated for differing seed values.");
            Assert.AreNotEqual(provider.LastCode, invalidProvider.LastCode, "Same last codes generated for differing seed values.");
            
            Assert.IsFalse(provider.Validate(invalidProvider.Code), "TOTP code with invalid seed validated against another TOTP provider.");
            Assert.IsFalse(provider.Validate(invalidProvider.LastCode), "TOTP last code with invalid seed validated against another TOTP provider.");

            Assert.IsFalse(provider.Validate(invalidProvider.Code, true), "TOTP code with invalid seed validated against another TOTP provider's last code.");
            Assert.IsFalse(provider.Validate(invalidProvider.LastCode, true), "TOTP last code with invalid seed validated against another TOTP provider's last code.");
        }
    }
}
