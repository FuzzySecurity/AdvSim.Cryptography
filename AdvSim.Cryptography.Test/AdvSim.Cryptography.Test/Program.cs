using System;
using System.Security.Cryptography;
using System.Text;

namespace AdvSim.Cryptography.Test
{
    internal static class Program
    {
        public static void Main(String[] args)
        {
            Byte[] bSampleData = Encoding.UTF32.GetBytes("Hello, I am a secret UTF32 message!");
            
            // AES
            Object oAESKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.AES_CBC);
            Byte[] bEnc = Symmetric.toAES(oAESKeyMat, bSampleData);
            Console.WriteLine("[+] AES Encrypted: \n" + hTest.HexDump(bEnc));
            Byte[] bDec = Symmetric.fromAES(oAESKeyMat, bEnc);
            Console.WriteLine("[+] AES Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // Triple DES
            Object oTDesKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.TRIPLE_DES);
            bEnc = Symmetric.toTripleDES(oTDesKeyMat, bSampleData);
            Console.WriteLine("[+] Triple DES Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Symmetric.fromTripleDES(oTDesKeyMat, bEnc);
            Console.WriteLine("[+] Triple DES Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // RC4
            Object oRC4KeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.RC4);
            bEnc = Symmetric.toRC4(oRC4KeyMat, bSampleData);
            Console.WriteLine("[+] RC4 Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Symmetric.fromRC4(oRC4KeyMat, bEnc);
            Console.WriteLine("[+] RC4 Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // RC2
            Object oRC2KeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.RC2);
            bEnc = Symmetric.toRC2(oRC2KeyMat, bSampleData);
            Console.WriteLine("[+] RC2 Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Symmetric.fromRC2(oRC2KeyMat, bEnc);
            Console.WriteLine("[+] RC2 Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // Multi Xor
            Object oXorKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.MULTI_XOR);
            bEnc = Symmetric.toMultiXOR(oXorKeyMat, bSampleData);
            Console.WriteLine("[+] Xor Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Symmetric.fromMultiXOR(oXorKeyMat, bEnc);
            Console.WriteLine("[+] Xor Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // XTEA
            Object oXTEAKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.XTEA);
            bEnc = Symmetric.toXTEA(oXTEAKeyMat, bSampleData);
            Console.WriteLine("[+] XTEA Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Symmetric.fromXTEA(oXTEAKeyMat, bEnc);
            Console.WriteLine("[+] XTEA Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
#if NETFRAMEWORK

            // DPAPI Machine
            bEnc = WindowsLocal.toMachineDPAPI(bSampleData);
            Console.WriteLine("[+] Machine DPAPI Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = WindowsLocal.fromMachineDPAPI(bEnc);
            Console.WriteLine("[+] Machine DPAPI Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // DPAPI Machine + entropy
            Byte[] bEntropy = WindowsLocal.generateEntropy("Hello Entropy");
            bEnc = WindowsLocal.toMachineDPAPI(bSampleData, bEntropy);
            Console.WriteLine("[+] Machine DPAPI Encrypted (+Entropy): \n" + hTest.HexDump(bEnc));
            bDec = WindowsLocal.fromMachineDPAPI(bEnc, bEntropy);
            Console.WriteLine("[+] Machine DPAPI Decrypted (+Entropy): \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // DPAPI User
            bEnc = WindowsLocal.toUserDPAPI(bSampleData);
            Console.WriteLine("[+] User DPAPI Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = WindowsLocal.fromUserDPAPI(bEnc);
            Console.WriteLine("[+] User DPAPI Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // DPAPI User + entropy
            bEntropy = WindowsLocal.generateEntropy("Hello Entropy");
            bEnc = WindowsLocal.toUserDPAPI(bSampleData, bEntropy);
            Console.WriteLine("[+] User DPAPI Encrypted (+Entropy): \n" + hTest.HexDump(bEnc));
            bDec = WindowsLocal.fromUserDPAPI(bEnc, bEntropy);
            Console.WriteLine("[+] User DPAPI Decrypted (+Entropy): \n" + Encoding.UTF32.GetString(bDec) + "\n");

#endif

#if NETFRAMEWORK || (NET6_0_OR_GREATER && WINDOWS)
            
            // ECDH
            Console.WriteLine("[+] Simulating ECDH Key Exchange..");
            ECDiffieHellmanCng oClient1ECDH = Asymmetric.initializeECDH();
            ECDiffieHellmanCng oClient2ECDH = Asymmetric.initializeECDH();
            
            Byte[] bClient1PubKey = Asymmetric.getECDHPublicKey(oClient1ECDH);
            Console.WriteLine("[>] Client 1 Public key: \n" + hTest.HexDump(bClient1PubKey));
            Byte[] bClient2PubKey = Asymmetric.getECDHPublicKey(oClient2ECDH);
            Console.WriteLine("[>] Client 2 Public key: \n" + hTest.HexDump(bClient2PubKey) + "\n");
            
            Asymmetric.ECDH_KEY_MAT oCLient1Shared = Asymmetric.deriveECDHSharedKeyMaterial(oClient1ECDH, bClient2PubKey);
            Console.WriteLine("[+] Client 1 Shared Key: " + BitConverter.ToString(oCLient1Shared.bKey));
            Console.WriteLine("                     IV: " + BitConverter.ToString(oCLient1Shared.bIV) + "\n");
            Asymmetric.ECDH_KEY_MAT oCLient2Shared = Asymmetric.deriveECDHSharedKeyMaterial(oClient2ECDH, bClient1PubKey);
            Console.WriteLine("[+] Client 2 Shared Key: " + BitConverter.ToString(oCLient2Shared.bKey));
            Console.WriteLine("                     IV: " + BitConverter.ToString(oCLient2Shared.bIV) + "\n");
            
            bEnc = Asymmetric.toECDH(oCLient1Shared, bSampleData);
            Console.WriteLine("[+] Client 1 Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Asymmetric.fromECDH(oCLient2Shared, bEnc);
            Console.WriteLine("[+] Client 2 Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
#endif
            
            // RSA
            Console.WriteLine("[+] Generating RSA Key Pair..");
            Asymmetric.RSA_KEY_MAT oRSAKeyMat = Asymmetric.initializeRSA();

            Byte[] bRSAPubKey = Asymmetric.getArrayFromRSAParameters(oRSAKeyMat.oPublicKey);
            Console.WriteLine("[>] RSA Public key: \n" + hTest.HexDump(bRSAPubKey));
            RSAParameters oPublicKey = Asymmetric.getRSAParametersFromArray(bRSAPubKey);

            bEnc = Asymmetric.toRSA(oPublicKey, bSampleData);
            Console.WriteLine("[+] RSA Encrypted: \n" + hTest.HexDump(bEnc));
            bDec = Asymmetric.fromRSA(oRSAKeyMat.oPrivateKey, bEnc);
            Console.WriteLine("[+] RSA Decrypted: \n" + Encoding.UTF32.GetString(bDec) + "\n");
            
            // TOTP
            Console.WriteLine("[+] TOTP generation");
            Miscellaneous.TOTP oTOTP = Miscellaneous.generateTOTP("Hello World");
            Console.WriteLine("[>] TOPT      Code: " + oTOTP.Code);
            Console.WriteLine("[>] TOPT Last Code: " + oTOTP.LastCode);
            Console.WriteLine("[>] TOPT  Validity: " + oTOTP.Seconds);
            
            Console.WriteLine("[?] Validate current TOTP: " + Miscellaneous.validateTOTP("Hello World", oTOTP.Code));
            Console.WriteLine("[?] Validate TOTP with forgiveness: " + Miscellaneous.validateTOTP("Hello World", oTOTP.LastCode, true));
            Console.WriteLine("[?] Validate invalid TOTP: " + Miscellaneous.validateTOTP("Hello World", oTOTP.LastCode));
        }
    }
}