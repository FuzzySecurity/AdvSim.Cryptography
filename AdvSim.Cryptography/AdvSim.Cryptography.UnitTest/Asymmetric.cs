using System;
using System.Text;
using NUnit.Framework;

namespace AdvSim.Cryptography.UnitTest
{
    public class Asymmetric
    {
        // Unit test globals
        //===================================
        private static Byte[] bTestData = Encoding.ASCII.GetBytes("Stones are all changed now in Nine grounds out of ten..");
    
        // Tests
        //===================================
    
        [Test]
        public void Test_RSA()
        {
            Console.WriteLine("[+] Testing RSA");
        
            RSA test = new RSA();
            Byte[] bPublicKey = test.GetPublicKeyArray();
        
            Byte[] bEncrypted = test.Encrypt(bPublicKey, bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
        
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
    
        [Test]
        public void Test_ECDH()
        {
            Console.WriteLine("[+] Testing ECDH");
#if NET47_OR_GREATER || NETSTANDARD2_1_OR_GREATER || NET6_0_OR_GREATER
            ECDH test1 = new ECDH(ECDH.ECCurveType.nistP521);
            ECDH test2 = new ECDH(ECDH.ECCurveType.nistP521);
#else
            ECDH test1 = new ECDH();
            ECDH test2 = new ECDH();
#endif
            Byte[] bPublic1 = test1.GetPublicKeyArray();
            Byte[] bPublic2 = test2.GetPublicKeyArray();

            test1.DeriveSharedKey(bPublic2);
            test2.DeriveSharedKey(bPublic1);

            Byte[] bEncrypted1 = test1.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted1).Replace("-", ""));
            Byte[] bEncrypted2 = test2.Encrypt(bTestData);
            
            Assert.That(bEncrypted1, Is.EqualTo(bEncrypted2));
        }
    }
}

