![Release](https://badgen.net/badge/AdvSim.Cryptography/v2.0.0/cyan?icon=github)
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
    - [Elliptic-curve Diffie–Hellman (ECDH)](#elliptic-curve-diffiehellman-ecdh)
    - [RSA](#rsa)
- [Windows Local](#windows-local)
    - [Entropy Generation](#entropy-generation)
    - [DPAPI Local Machine](#dpapi-local-machine)
    - [DPAPI Current User](#dpapi-current-user)
- [Miscellaneous](#miscellaneous)
    - [TOTP](#totp)

#### NuGet Compatibility

The `AdvSim.Cryptography` NuGet supports a wide variety of .Net versions. Generally functions included in the library have good coverage across target frameworks. Where functions are restricted to specific frameworks, a badge has been added to highlight that dependency.

***NuGet URL***: https://www.nuget.org/packages/AdvSim.Cryptography

#### Key Material

Where key material is provided as part of the cryptographic constructor, `Rfc2898DeriveBytes` is used to return pseudo-random byte arrays to seed the encryption and decryption operations. These byte arrays are high quality while also ensuring that calling the same function with the same key material will result in the same pseudo-random seed.

# Usage

## Symmetric

#### AES

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using the key material provided in the constructor. On completion it will return a byte array.

```cs
AES test = new AES("Lovecraft");
Byte[] bEncrypted = test.Encrypt(bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

#### Triple DES

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using the key material provided in the constructor. On completion it will return a byte array.

```cs
TripleDES test = new TripleDES("Lovecraft");
Byte[] bEncrypted = test.Encrypt(bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

#### RC4

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using the key material provided in the constructor. On completion it will return a byte array.

```cs
RC4 test = new RC4("Lovecraft");
Byte[] bEncrypted = test.Encrypt(bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

#### RC2

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using the key material provided in the constructor. On completion it will return a byte array.

```cs
RC2 test = new RC2("Lovecraft");
Byte[] bEncrypted = test.Encrypt(bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

#### Multi-Byte XOR

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using the key material provided in the constructor. On completion it will return a byte array.

```cs
MultiXOR test = new MultiXOR("Lovecraft");
Byte[] bEncrypted = test.Encrypt(bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

#### XTEA

![Availability](https://badgen.net/badge/Availability/All/green)

This function takes a byte array and will either encrypt or decrypt it using the key material provided in the constructor. On completion it will return a byte array.

```cs
XTEA test = new XTEA("jumanji");
Byte[] bEncrypted = test.Encrypt(bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

## Asymmetric

### Elliptic-curve Diffie–Hellman (ECDH)

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK%20%3C%20NET47/green) ![Availability](https://badgen.net/badge/Availability/NET47_OR_GREATER%20%7C%7C%20NETSTANDARD2_1_OR_GREATER%20%7C%7C%20NET6_0_OR_GREATER/green)

Note here that in `v2.0.0` ECDH is supported across all .Net versions available in the NuGet. However, because of some really questionable .Net design decisions it is non-trivial to get interop between all supported targets.

As a result there are implementation differences between `Framework < .Net 4.7` and everything else. Both clients should fall into the same group to successfully perform a key exchange. If, for example, you need one client to be on `.Net 6` and another on `.Net 4.5.1` then you should use `RSA` instead.

To understand more about .Net versioning you can consult the following resource.

- [https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies](https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies)

#### Usage

***Framework < .Net 4.7***

These targets only support `nistP256` and can use the library as follows.

```cs
// Initialize both clients
ECDH test1 = new ECDH();
ECDH test2 = new ECDH();

// Exchange public keys
Byte[] bPublic1 = test1.GetPublicKeyArray();
Byte[] bPublic2 = test2.GetPublicKeyArray();

// Derive
test1.DeriveSharedKey(bPublic2);
test2.DeriveSharedKey(bPublic1);

// Encrypt / Decrypt
Byte[] bEncrypted1 = test1.Encrypt(bTestData);
Byte[] bDecrypted2 = test2.Decrypt(bEncrypted1);
```

***.Net 4.7+  || Standard 2.1 || .Net 6***

These targets take a curve as an argument for the constructor.

```cs
public enum ECCurveType  
{  
    brainpoolP160r1,  
    brainpoolP160t1,  
    brainpoolP192r1,  
    brainpoolP192t1,  
    brainpoolP224r1,  
    brainpoolP224t1,  
    brainpoolP256r1,  
    brainpoolP256t1,  
    brainpoolP320r1,  
    brainpoolP320t1,  
    brainpoolP384r1,  
    brainpoolP384t1,  
    brainpoolP512r1,  
    brainpoolP512t1,  
    nistP256,  
    nistP384,  
    nistP521  
}
```

Usage is shown below.

```cs
// Initialize both clients
ECDH test1 = new ECDH(ECDH.ECCurveType.nistP521);
ECDH test2 = new ECDH(ECDH.ECCurveType.nistP521);

// Exchange public keys
Byte[] bPublic1 = test1.GetPublicKeyArray();
Byte[] bPublic2 = test2.GetPublicKeyArray();

// Derive
test1.DeriveSharedKey(bPublic2);
test2.DeriveSharedKey(bPublic1);

// Encrypt / Decrypt
Byte[] bEncrypted1 = test1.Encrypt(bTestData);
Byte[] bDecrypted2 = test2.Decrypt(bEncrypted1);
```

### RSA

![Availability](https://badgen.net/badge/Availability/All/green)

Note that this functionality does necessarily require two clients since public keys do not have to be exchanged to derive a shared secret as is the case for ECDH. Of course as above you can send your public key on the wire to a different client who can then encrypt data only you can decrypt.

#### Usage

```cs
RSA test = new RSA();
Byte[] bPublicKey = test.GetPublicKeyArray();
Byte[] bEncrypted = test.Encrypt(bPublicKey, bTestData);
Byte[] bDecrypted = test.Decrypt(bEncrypted);
```

## Windows Local

#### DPAPI Local Machine

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

Data that is encrypted and decrypted is scoped to the machine. Data cannot be decrypted off-host.

```cs
// Without entropy
DPAPI test = new DPAPI();
Byte[] bEncrypted = test.EncryptUserDPAPI(bTestData);
Byte[] bDecrypted = test.DecryptUserDPAPI(bEncrypted);

// With entropy
DPAPI test = new DPAPI("Lovecraft");
Byte[] bEncrypted = test.EncryptUserDPAPI(bTestData);
Byte[] bDecrypted = test.DecryptUserDPAPI(bEncrypted);
```

#### DPAPI Current User

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

Data that is encrypted and decrypted is scoped to the current user. Data cannot be decrypted in a different user context.

```cs
// Without entropy
DPAPI test = new DPAPI();
Byte[] bEncrypted = test.EncryptMachineDPAPI(bTestData);
Byte[] bDecrypted = test.DecryptMachineDPAPI(bEncrypted);

// With entropy
DPAPI test = new DPAPI("Lovecraft");
Byte[] bEncrypted = test.EncryptMachineDPAPI(bTestData);
Byte[] bDecrypted = test.DecryptMachineDPAPI(bEncrypted);
```

## Miscellaneous

### TOTP

![Availability](https://badgen.net/badge/Availability/All/green)

A time-based one-time password (TOTP) can be used as an additional check when performing actions to validate that they are authentic. TOTP's generated by the library are valid for a full `UtcNow` minute. These numeric secrets can also be used to dynamically seed rotating keys for symmetric encryption algorithms. If clients use the same seed on different machines, they will receive the same TOTP.

#### Usage

```cs
// Generate a TOTP using a string seed
TOTP test = new TOTP("Lovecraft");
Console.WriteLine("[+] TOPT Code     : "  + oOTP.Code);
Console.WriteLine("[+] TOPT Last Code: "  + oOTP.LastCode);
Console.WriteLine("[+] TOPT Validity : "  + oOTP.Seconds);

// Validate TOTP based on string seed
Boolean bValid = test.ValidateTOTP("Lovecraft", oTOTP.Code);

// Validate TOTP with forgiveness, this allows the previous TOTP
// to also be counted as valid
Boolean bValid = test.ValidateTOTP("Lovecraft", oTOTP.LastCode, true);
```