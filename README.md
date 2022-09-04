![Release](https://badgen.net/badge/AdvSim.Cryptography/v1.0.0/cyan?icon=github)
# AdvSim.Cryptography

The `AdvSim.Cryptography` NuGet contains a set of cryptographic wrapper functions which are reusable, configured with sane defaults and are easy to use. Further details are available under the different subheadings below.

- [Symmetric](#symmetric)
    - [Key Material Generation](#key-material-generation)
    - [AES](#aes)
    - [Triple DES](#triple-des)
    - [RC4](#rc4)
    - [RC2](#rc2)
    - [Multi-Byte XOR](#multi-byte-xor)
    - [XTEA](#xtea)
- [Asymmetric](#asymmetric)
    - [Elliptic-curve Diffie–Hellman (ECDH) to AES-CBC](#)
    - [RSA](#rsa)
- [Windows Local](#windows-local)
    - [Entropy Generation](#entropy-generation)
    - [DPAPI Local Machine](#dpapi-local-machine)
    - [DPAPI Current User](#dpapi-current-user)
- [Miscellaneous](#miscellaneous)
    - [TOTP](#totp)

#### NuGet Compatibility

The `AdvSim.Cryptography` NuGet supports a wide variety of .Net versions. Generally functions included in the library have good coverage across target frameworks. Where functions are restricted to specific frameworks, a badge has been added to highlight that dependency.

**NuGet URL**: https://www.nuget.org/packages/AdvSim.Cryptography

# Usage

## Symmetric

#### Key Material Generation

![Availability](https://badgen.net/badge/Availability/All/green)

`Symmetric.generateKeyMaterial` is used to generate all key material for the Symmetric cryptographic operations. This function takes a `String` seed input and the type of cryptographic operation for which the key material will be used. The returned key material is pseudo-random (using `Rfc2898DeriveBytes`). The key material is high quality but also using a string seed guarantees that if the function is called somewhere else with the same seed that the same key material will be generated.

```cs
Object oAESKeyMat  = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.AES_CBC);
Object oTDesKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.TRIPLE_DES);
Object oRC4KeyMat  = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.RC4);
Object oRC2KeyMat  = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.RC2);
Object oXorKeyMat  = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.MULTI_XOR);
Object oXTEAKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.XTEA);
```

#### AES

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using previously generated key material. On completion it will return a byte array.

```cs
Object oAESKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.AES_CBC);
Byte[] bEnc = Symmetric.toAES(oAESKeyMat, bSampleData);
Byte[] bDec = Symmetric.fromAES(oAESKeyMat, bEnc);
```

#### Triple DES

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using previously generated key material. On completion it will return a byte array.

```cs
Object oTDesKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.TRIPLE_DES);
Byte[] bEnc = Symmetric.toTripleDES(oTDesKeyMat, bSampleData);
Byte[] bDec = Symmetric.fromTripleDES(oTDesKeyMat, bEnc);
```

#### RC4

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using previously generated key material. On completion it will return a byte array.

```cs
Object oRC4KeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.RC4);
Byte[] bEnc = Symmetric.toRC4(oRC4KeyMat, bSampleData);
Byte[] bDec = Symmetric.fromRC4(oRC4KeyMat, bEnc);
```

#### RC2

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using previously generated key material. On completion it will return a byte array.

```cs
Object oRC2KeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.RC2);
Byte[] bEnc = Symmetric.toRC2(oRC2KeyMat, bSampleData);
Byte[] bDec = Symmetric.fromRC2(oRC2KeyMat, bEnc);
```

#### Multi-Byte XOR

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using previously generated key material. On completion it will return a byte array.

```cs
Object oXorKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.MULTI_XOR);
Byte[] bEnc = Symmetric.toMultiXOR(oXorKeyMat, bSampleData);
Byte[] bDec = Symmetric.fromMultiXOR(oXorKeyMat, bEnc);
```

#### XTEA

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using previously generated key material. On completion it will return a byte array.

```cs
Object oXTEAKeyMat = Symmetric.generateKeyMaterial("Hello World", Symmetric.CryptographyType.XTEA);
Byte[] bEnc = Symmetric.toXTEA(oXTEAKeyMat, bSampleData);
Byte[] bDec = Symmetric.fromXTEA(oXTEAKeyMat, bEnc);
```

## Asymmetric

### Elliptic-curve Diffie–Hellman (ECDH) to AES-CBC

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green) ![Availability](https://badgen.net/badge/Availability/NET6_0_OR_GREATER%20&&%20WINDOWS/green)

Note that this functionality requires two clients. It is ideal when negotiation cryptography over the wire. Both clients initialize randomized EHDC keypairs, they exchange public keys and finally they are able to derive a `shared secret`. This secret can then be used to perform symmetric encryption of data that both clients can access.

#### Usage

```cs
// Both clients generate randomized key material
ECDiffieHellmanCng oClient1ECDH = Asymmetric.initializeECDH();
ECDiffieHellmanCng oClient2ECDH = Asymmetric.initializeECDH();

// Both clients extract the public key from they key material
// |_ These keys can be exchanged over a transport
Byte[] bClient1PubKey = Asymmetric.getECDHPublicKey(oClient1ECDH);
Byte[] bClient2PubKey = Asymmetric.getECDHPublicKey(oClient2ECDH);

// Both clients incorporate the public key of the other party to
// derive a shared secret
Asymmetric.ECDH_KEY_MAT oCLient1Shared = Asymmetric.deriveECDHSharedKeyMaterial(oClient1ECDH, bClient2PubKey);
Asymmetric.ECDH_KEY_MAT oCLient2Shared = Asymmetric.deriveECDHSharedKeyMaterial(oClient2ECDH, bClient1PubKey);

// Client 1 uses AES-CBC to encrypt data using the shared secret
Byte[] bEnc = Asymmetric.toECDH(oCLient1Shared, bSampleData);

// Client 2 uses AES-CBC to decrypt data using the shared secret
Byte[] bDec = Asymmetric.fromECDH(oCLient2Shared, bEnc);
```

### RSA

![Availability](https://badgen.net/badge/Availability/All/green)

Note that this functionality does not always require two clients since public keys do not have to be exchanged to derive a shared secret as is the case for ECDH. Of course as above you can send your public key on the wire to a different client who can then encrypt data only you can decrypt.

#### Usage

```cs
// The client initializes randomized key material
// |_ Note that the return object has properties for the public
//    and private keys
Asymmetric.RSA_KEY_MAT oRSAKeyMat = Asymmetric.initializeRSA();

// The RSA public key can be turned into a byte array and back
// to an RSAParameters object for key exchange purposes
Byte[] bRSAPubKey = Asymmetric.getArrayFromRSAParameters(oRSAKeyMat.oPublicKey);
RSAParameters oPublicKey = Asymmetric.getRSAParametersFromArray(bRSAPubKey);

// The client encrypts data using a public key
// |_ Either the clients own key or one recieved over the wire
Byte[] bEnc = Asymmetric.toRSA(oRSAKeyMat.oPublicKey, bSampleData);
Byte[] bEnc = Asymmetric.toRSA(oPublicKey, bSampleData);

// The client decrypts data using their private key
Byte[] bDec = Asymmetric.fromRSA(oRSAKeyMat.oPrivateKey, bEnc);
```

## Windows Local

#### Entropy Generation

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

`WindowsLocal.generateEntropy` is used to generate optional entropy which can be used when encrypting or decrypting using DPAPI. DPAPI entropy does not have a length limit, by default this function generates 32-bytes of entropy however the amount of entropy can be specified when calling the function. The returned entropy is pseudo-random (using `Rfc2898DeriveBytes`). The entropy is high quality but also using a string seed guarantees that if the function is called somewhere else with the same seed that the same entropy will be generated.

```cs
// Default 32-byte entropy
Byte[] bEntropy = WindowsLocal.generateEntropy("Hello Entropy");

// Custom 100-byte entropy
Byte[] bEntropy = WindowsLocal.generateEntropy("Hello Entropy", 100);
```

#### DPAPI Local Machine

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

Data that is encrypted and decrypted is scoped to the machine. Data cannot be decrypted off-host.

```cs
// Without entropy
Byte[] bEnc = WindowsLocal.toMachineDPAPI(bSampleData);
Byte[] bDec = WindowsLocal.fromMachineDPAPI(bEnc);

// With entropy
Byte[] bEntropy = WindowsLocal.generateEntropy("Hello Entropy");
Byte[] bEnc = WindowsLocal.toMachineDPAPI(bSampleData, bEntropy);
Byte[] bDec = WindowsLocal.fromMachineDPAPI(bEnc, bEntropy);
```

#### DPAPI Current User

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

Data that is encrypted and decrypted is scoped to the current user. Data cannot be decrypted in a different user context.

```cs
// Without entropy
Byte[] bEnc = WindowsLocal.toUserDPAPI(bSampleData);
Byte[] bDec = WindowsLocal.fromUserDPAPI(bEnc);

// With entropy
Byte[] bEntropy = WindowsLocal.generateEntropy("Hello Entropy");
Byte[] bEnc = WindowsLocal.toUserDPAPI(bSampleData, bEntropy);
Byte[] bDec = WindowsLocal.fromUserDPAPI(bEnc, bEntropy);
```

## Miscellaneous

### TOTP

![Availability](https://badgen.net/badge/Availability/All/green)

A time-based one-time password (TOTP) can be used as a an additional check when performing actions to validate that they are authentic. TOTP's generated by the function below are valid for a full `UtcNow` minute. These numeric secrets can also be used to dynamically seed rotating keys for symmetric encryption algorithms. If clients use the same seed on different machines, they will receive the same TOTP.

#### Usage

```cs
// Generate a TOTP using a string seed
Miscellaneous.TOTP oTOTP = Miscellaneous.generateTOTP("Hello World");
Console.WriteLine("[+] TOPT Code     : "  + oTOTP.Code);
Console.WriteLine("[+] TOPT Last Code: "  + oTOTP.LastCode);
Console.WriteLine("[+] TOPT Validity : "  + oTOTP.Seconds);

// Validate TOTP based on string seed
Boolean bValid = Miscellaneous.validateTOTP("Hello World", oTOTP.Code);

// Validate TOTP with forgiveness, this allows the previous TOTP
// to also be counted as valid
Boolean bValid = Miscellaneous.validateTOTP("Hello World", oTOTP.Code, true);
```