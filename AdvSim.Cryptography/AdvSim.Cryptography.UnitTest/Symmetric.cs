using System;
using System.Text;
using NUnit.Framework;
using AdvSim.Cryptography;

namespace AdvSim.Cryptography.UnitTest
{
    public class Symmetric
    {
        // Unit test globals
        //===================================
        private static Byte[] bTestData = Encoding.ASCII.GetBytes("Stones are all changed now in Nine grounds out of ten..");
        
        // Tests
        //===================================
    
        [Test]
        public void Test_AES()
        {
            Console.WriteLine("[+] Testing AES");
            
            AES test = new AES("jumanji");
            Byte[] bEncrypted = test.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
        
        [Test]
        public void Test_TDES()
        {
            Console.WriteLine("[+] Testing TripleDES");
            
            TripleDES test = new TripleDES("jumanji");
            Byte[] bEncrypted = test.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
        
        [Test]
        public void Test_RC4()
        {
            Console.WriteLine("[+] Testing RC4");
            
            RC4 test = new RC4("jumanji");
            Byte[] bEncrypted = test.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
        
        [Test]
        public void Test_RC2()
        {
            Console.WriteLine("[+] Testing RC2");
            
            RC2 test = new RC2("jumanji");
            Byte[] bEncrypted = test.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
        
        [Test]
        public void Test_MultiXOR()
        {
            Console.WriteLine("[+] Testing MultiXOR");
            
            MultiXOR test = new MultiXOR("jumanji");
            Byte[] bEncrypted = test.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
        
        [Test]
        public void Test_XTEA()
        {
            Console.WriteLine("[+] Testing XTEA");
            
            XTEA test = new XTEA("jumanji");
            Byte[] bEncrypted = test.Encrypt(bTestData);
            Console.WriteLine(BitConverter.ToString(bEncrypted).Replace("-", ""));
            Byte[] bDecrypted = test.Decrypt(bEncrypted);
            
            Assert.That(bDecrypted, Is.EqualTo(bTestData));
        }
    }
}

