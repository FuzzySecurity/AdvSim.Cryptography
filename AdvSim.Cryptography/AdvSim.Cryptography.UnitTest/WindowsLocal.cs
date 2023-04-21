using System;
using System.Text;
using NUnit.Framework;

namespace AdvSim.Cryptography.UnitTest
{
    public class WindowsLocal
    {
        // Unit test globals
        //===================================
        private static Byte[] bTestData = Encoding.ASCII.GetBytes("Stones are all changed now in Nine grounds out of ten..");
        
        // Tests
        //===================================
        
#if NETFRAMEWORK
        [Test]
        public void Test_DPAPI()
        {
            Console.WriteLine("[+] Testing DPAPI User no entropy");
            
            DPAPI test = new DPAPI();
            Byte[] bEncrypted = test.EncryptUserDPAPI(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.DecryptUserDPAPI(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
        
        [Test]
        public void Test_DPAPI_Entropy()
        {
            Console.WriteLine("[+] Testing DPAPI Machine with entropy");
            
            DPAPI test = new DPAPI("jumanji");
            Byte[] bEncrypted = test.EncryptMachineDPAPI(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.DecryptMachineDPAPI(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
#endif
    }
}