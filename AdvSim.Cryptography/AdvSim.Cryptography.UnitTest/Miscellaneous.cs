using System;
using NUnit.Framework;

namespace AdvSim.Cryptography.UnitTest
{
    public class Miscellaneous
    {
        [Test]
        public void Test_TOTP()
        {
            Console.WriteLine("[+] Testing TOTP");
            
            TOTP test = new TOTP("jumanji");
            TOTP.OTP oOTP = test.GenerateTOTP();
            TOTP test2 = new TOTP("jumanji");
            TOTP.OTP oOTP2 = test2.GenerateTOTP();
            
            Console.WriteLine("OTP: {0}", oOTP.Code);
            Console.WriteLine("Last OTP: {0}", oOTP.LastCode);
            Console.WriteLine("Seconds: {0}", oOTP.Seconds);
            
            Assert.That(oOTP.Code, Is.EqualTo(oOTP2.Code));
        }
        
        [Test]
        public void Test_TOTP2()
        {
            Console.WriteLine("[+] Testing TOTP");
            
            TOTP test = new TOTP("jumanji");
            TOTP.OTP oOTP = test.GenerateTOTP();
            TOTP test2 = new TOTP("MarstenHouse");
            TOTP.OTP oOTP2 = test2.GenerateTOTP();
            
            Console.WriteLine("[+] Test 1");
            Console.WriteLine("OTP: {0}", oOTP.Code);
            Console.WriteLine("Last OTP: {0}", oOTP.LastCode);
            Console.WriteLine("Seconds: {0}", oOTP.Seconds);
            
            Console.WriteLine("[+] Test 2");
            Console.WriteLine("OTP: {0}", oOTP2.Code);
            Console.WriteLine("Last OTP: {0}", oOTP2.LastCode);
            Console.WriteLine("Seconds: {0}", oOTP2.Seconds);
            
            Assert.That(oOTP.Code, Is.Not.EqualTo(oOTP2.Code));
        }
    }
}