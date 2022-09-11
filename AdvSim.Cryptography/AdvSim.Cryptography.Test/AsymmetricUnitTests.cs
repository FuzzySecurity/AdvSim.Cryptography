using AdvSim.Cryptography.Asymmetric;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace AdvSim.Cryptography.Test
{
    /// <summary>
    /// Summary description for UnitTest1
    /// </summary>
    [TestClass]
    public class AsymmetricUnitTests
    {
        private const string _message = "Keep me a secret!";
        private byte[] _bMessage = Encoding.UTF8.GetBytes(_message);
        public AsymmetricUnitTests()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void TestECDiffieHellmanProvider()
        {
            ECDiffieHellmanProvider client = new ECDiffieHellmanProvider();
            ECDiffieHellmanProvider server = new ECDiffieHellmanProvider();
            
            ECDiffieHellmanProvider.DeriveSharedKey(ref client, ref server);
            
            ICryptographicProviderTest testAfterDerivation = new ICryptographicProviderTest(client);
            testAfterDerivation.Test();

            // Don't need to check result of client.Encrypt as testAfterDerivation should
            // do these sanity checks
            byte[] bEnc = client.Encrypt(_bMessage);
            byte[] bDec = server.Decrypt(bEnc);

            string result = Encoding.UTF8.GetString(bDec);
            Assert.AreEqual(_message, result, "Client and server key negotiation failed to establish a common key.");
        }

        [TestMethod]
        public void TestRSAProvider()
        {
            RSAProvider server = new RSAProvider();
            ICryptographicProviderTest tester = new ICryptographicProviderTest(server);
            tester.Test();

            byte[] bPub = server.ExportPublicKey();
            Assert.AreNotEqual(bPub.Length, 0, "Failed to export public key as bytes.");

            RSAProvider client = new RSAProvider(bPub);
            byte[] bEnc = client.Encrypt(_bMessage);
            Assert.AreNotEqual(_bMessage, bEnc, "Message failed to be encrypted.");
            Assert.AreNotEqual(bEnc.Length, 0, "Encryption returned message of zero bytes.");

            byte[] bDec = server.Decrypt(bEnc);
            string result = Encoding.UTF8.GetString(bDec);
            Assert.AreEqual(result, _message, "Server did not decode message from client properly.");
        }
    }
}
