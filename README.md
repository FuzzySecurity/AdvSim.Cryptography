![Release](https://badgen.net/badge/AdvSim.Cryptography/v1.0.0/cyan?icon=github)
# AdvSim.Cryptography

The `AdvSim.Cryptography` NuGet contains a set of cryptographic wrapper functions which are reusable, configured with sane defaults and are easy to use. Further details are available under the different subheadings below.

- [Symmetric](#symmetric)
    - [AES](#aes)
    - [Triple DES](#triple-des)
    - [RC4](#rc4)
    - [RC2](#rc2)
    - [Multi-Byte XOR](#multi-byte-xor)
    - [XTEA](#xtea)
- [Asymmetric](#asymmetric)
    - [Elliptic-curve Diffie–Hellman (ECDH) to AES-CBC](#elliptic-curve-diffiehellman-ecdh-to-aes-cbc)
    - [RSA](#rsa)
- [Windows Local](#windows-local)
    - [DPAPI Local Machine](#dpapi-local-machine)
    - [DPAPI Current User](#dpapi-current-user)
- [Miscellaneous](#miscellaneous)
    - [TOTP](#totp)

#### NuGet Compatibility

The `AdvSim.Cryptography` NuGet supports a wide variety of .Net versions. Generally functions included in the library have good coverage across target frameworks. Where functions are restricted to specific frameworks, a badge has been added to highlight that dependency.

**NuGet URL**: https://www.nuget.org/packages/AdvSim.Cryptography

# Usage

## AdvSim.Cryptography.Symmetric

### AES

![Availability](https://badgen.net/badge/Availability/All/green)

AES encryption is governed by the AESProvider class. The constructor takes a string password or from a provided key and initialization vector.

#### Usage

```cs
using System.Cryptography.Symmetric;

AESProvider provider = new AESProvider("Hello World");
byte[] bEnc = provider.Encrypt(
    System.Text.Encoding.UTF8.GetBytes("My Secret Message")
);
byte[] bDec = provider.Decrypt(bEnc);
```

### Triple DES

![Availability](https://badgen.net/badge/Availability/All/green)

Triple DES encryption is goverened by the TripleDESProvider class. The constructor takes either a string password or from a provided key and initialization vector.

#### Usage

```cs
using System.Cryptography.Symmetric;

TripleDESProvider provider = new TripleDESProvider("Hello World");
byte[] bEnc = provider.Encrypt(
    System.Text.Encoding.UTF8.GetBytes("My Secret Message")
);
byte[] bDec = provider.Decrypt(bEnc);
```

### RC4

![Availability](https://badgen.net/badge/Availability/All/green)

RC4 encryption is goverened by the RC4Provider class. The constructor takes either a string password or from a provided key.

#### Usage

```cs
RC4Provider provider = new RC4Provider("Hello World");
byte[] bEnc = provider.Encrypt(
    System.Text.Encoding.UTF8.GetBytes("My Secret Message")
);
byte[] bDec = provider.Decrypt(bEnc);
```

### RC2

![Availability](https://badgen.net/badge/Availability/All/green)

RC2 encryption is goverened by the RC2Provider class. The constructor takes either a string password or from a provided key and initialization vector.

#### Usage

```cs
RC2Provider provider = new RC2Provider("Hello World");
byte[] bEnc = provider.Encrypt(
    System.Text.Encoding.UTF8.GetBytes("My Secret Message")
);
byte[] bDec = provider.Decrypt(bEnc);
```

### Multi-Byte XOR

![Availability](https://badgen.net/badge/Availability/All/green)

Multi-Byte XOR encryption is goverened by the MultiByteXORProvider class. The constructor takes a string password and optional key length.

#### Usage

```cs
MultiByteXORProvider provider = new MultiByteXORProvider("Hello World");
byte[] bEnc = provider.Encrypt(
    System.Text.Encoding.UTF8.GetBytes("My Secret Message")
);
byte[] bDec = provider.Decrypt(bEnc);
```

### XTEA

![Availability](https://badgen.net/badge/Availability/All/green)

XTEA encryption is goverened by the XTEAProvider class. The constructor takes a string password and optional key length.

#### Usage
```cs
XTEAProvider provider = new XTEAProvider("Hello World");
byte[] bEnc = provider.Encrypt(
    System.Text.Encoding.UTF8.GetBytes("My Secret Message")
);
byte[] bDec = provider.Decrypt(bEnc);
```

## Asymmetric

### Elliptic-curve Diffie–Hellman (ECDH) to AES-CBC

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green) ![Availability](https://badgen.net/badge/Availability/NET6_0_OR_GREATER%20&&%20WINDOWS/green)

Note that this functionality requires two clients. It is ideal when negotiation cryptography over the wire. Both clients initialize randomized EHDC keypairs, they exchange public keys and finally they are able to derive a `shared secret`. This secret can then be used to perform symmetric encryption of data that both clients can access.

#### Usage

The following example is pseudo-code to allow for client/server key exchange to negotiate a shared secret.

```cs
using AdvSim.Cryptography.Asymmetric;

string message = "Keep me a secret!"
byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(message);

// Generate randomized key material
ECDiffieHellmanProvider client = new ECDiffieHellmanProvider();

// Result of this function should be the server-side ECDiffieHellmanProvider's
// public key. In this handshake exchange your client should send their
// public key so the server can derive the shared secret.
byte[] serverPublicKey = ExchangePublicKeys(client.GetPublicKey())

client.DeriveSharedKey(serverPublicKey);

// Say the server sends you some encrypted data and you pull those encrypted
// bytes from the network.
byte[] bEnc = GetServerMessage();
// The client can now decrypt as the exchange has been performed.
byte[] bDec = client.Decrypt(bEnc);

string result = Encoding.UTF8.GetString(bDec);
```

The following example assumes the client and server cryptography providers are localized to your application.

```cs
using AdvSim.Cryptography.Asymmetric;

string message = "Keep me a secret!"
byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(message);

// Generate randomized key material
ECDiffieHellmanProvider client = new ECDiffieHellmanProvider();
ECDiffieHellmanProvider server = new ECDiffieHellmanProvider();

// If localized, can use the static builtin helper function
ECDiffieHellmanProvider.DeriveSharedKey(ref client, ref server);

// Don't need to check result of client.Encrypt as testAfterDerivation should
// do these sanity checks
byte[] bEnc = client.Encrypt(_bMessage);
byte[] bDec = server.Decrypt(bEnc);

string result = Encoding.UTF8.GetString(bDec);
```

### RSA

![Availability](https://badgen.net/badge/Availability/All/green)

Note that this functionality does not always require two clients since public keys do not have to be exchanged to derive a shared secret as is the case for ECDH. Of course as above you can send your public key on the wire to a different client who can then encrypt data only you can decrypt.

#### Usage

```cs
using AdvSim.Cryptography.Asymmetric;

string message = "Hello world!";
byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(message);

// The client initializes randomized key material
// |_ Note that the return object has properties for the public
//    and private keys, but only the public key is publicly
//    accessible
RSAProvider provider = new RSAProvider();

// The RSA public key can be retrieved by the PublicKey attribute
// on the class object, or exported as a byte array via the 
// ExportPublicKey function.
Byte[] bRSAPubKey = provider.ExportPublicKey();
RSAParameters oPublicKey = provider.PublicKey;

// If you have a key provided to you, you
// can use an alternative constructor to initialize the RSAProvider
byte[] bPublicKey = new byte[] { ... };
byte[] bPrivateKey = new byte[] { ... };

// Initialize RSAProvider with RSAParameters object
RSAProvider encryptor = new RSAProvider(oPublicKey);
// Initialize RSAProvider object with public key bytes to encrypt data.
encryptor = new RSAProvider(bPublicKey);
// Initialize RSAProvider object with private key bytes to encrypt/decrypt data.
RSAProvider decryptor = new RSAProvider(bPrivateKey, false);

// The client encrypts data using a public key
// |_ Either the clients own key or one recieved over the wire
Byte[] bEnc = provider.Encrypt(bMessage);
bEnc = encryptor.Encrypt(bMessage);

// The client decrypts data using their private key
Byte[] bDec = provider.Decrypt(bEnc);
bDec = decryptor.Decrypt(bEnc);
```

## Windows Local

### DPAPI Local Machine

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

Data that is encrypted and decrypted is scoped to the machine. Data cannot be decrypted off-host.

```cs
using AdvSim.Cryptography.Windows;

string message = "Hello world!";
byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(message);

// Without entropy
MachineDPAPIProvider prov = new MachineDPAPIProvider();
// With entropy (default 32 bytes in length)
MachineDPAPIProvider prov = new MachineDPAPIProvider("Hello Entropy");

Byte[] bEnc = prov.Encrypt(bMessage);
Byte[] bDec = prov.Decrypt(bEnc);
```

#### DPAPI Current User

![Availability](https://badgen.net/badge/Availability/NETFRAMEWORK/green)

Data that is encrypted and decrypted is scoped to the current user. Data cannot be decrypted in a different user context.

```cs
using AdvSim.Cryptography.Windows;

string message = "Hello world!";
byte[] bMessage = System.Text.Encoding.UTF8.GetBytes(message);

// Without entropy
UserDPAPIProvider prov = new UserDPAPIProvider();
// With entropy (default 32 bytes in length)
UserDPAPIProvider prov = new UserDPAPIProvider("Hello Entropy");

Byte[] bEnc = prov.Encrypt(bMessage);
Byte[] bDec = prov.Decrypt(bEnc);
```

## Miscellaneous

### TOTP

![Availability](https://badgen.net/badge/Availability/All/green)

A time-based one-time password (TOTP) can be used as a an additional check when performing actions to validate that they are authentic. TOTP's generated by the function below are valid for a full `UtcNow` minute. These numeric secrets can also be used to dynamically seed rotating keys for symmetric encryption algorithms. If clients use the same seed on different machines, they will receive the same TOTP.

#### Usage

```cs
using AdvSim.Cryptography.Miscellaneous;

string seed = "Hello, World!";

// Generate client/server TOTP objects using the same seed
TOTP oClientTOTP = new TOTP(seed);
TOTP oServerTOTP = new TOTP(seed);

// Show current codes
Console.WriteLine("[+] TOPT Code     : "  + oServerTOTP.Code);
Console.WriteLine("[+] TOPT Last Code: "  + oServerTOTP.LastCode);
Console.WriteLine("[+] TOPT Validity : "  + oServerTOTP.Seconds);

// Validate TOTP based on string seed
Boolean bValid = oServerTOTP.Validate(oClientTOTP.Code);

// Validate TOTP with forgiveness, this allows the previous TOTP
// to also be counted as valid
Boolean bValid = oServerTOTP.Validate(oClientTOTP.Code, true);
```