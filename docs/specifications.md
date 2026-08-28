# Bouncy Castle Crypto Package

## 1.0 Introduction

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms. The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, see [here](../LICENSE.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/).

If you have the full package you will have six jar files, bcprov\*.jar which contains the BC provider, jce-\*.jar which contains the JCE provider, clean room API, and bcmail\*.jar which contains the mail API.

Note: if you are using JDK 1.0, you will just find a class hierarchy in the classes directory.

To view examples, look at the test programs in the packages:

- **org.bouncycastle.crypto.test**
- **org.bouncycastle.jce.provider.test**

To verify the packages, run the following Java programs with the appropriate classpath:

- **java org.bouncycastle.crypto.test.RegressionTest**
- **java org.bouncycastle.jce.provider.test.RegressionTest**

## 2.0 Patents

Some of the algorithms in the Bouncy Castle APIs are patented in some places. It is upon the user of the library to be aware of what the legal situation is in their own situation, however we have been asked to specifically mention the patents below, in the following terms, at the request of the patent holder.

The BC distribution contains implementations of EC MQV as described in RFC 5753, "Use of ECC Algorithms in CMS". In line with the conditions in:

    https://www.ietf.org/ietf-ftp/IPR/certicom-ipr-rfc-5753.pdf

We state, where EC MQV has not otherwise been disabled or removed: "The use of this product or service is subject to the reasonable, non-discriminatory terms in the Intellectual Property Rights (IPR) Disclosures of Certicom Corp. at the IETF for Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS) implemented in the product or service."

## 3.0 System Properties

The Bouncy Castle provider can make use of the following two system properties:

- **org.bouncycastle.ec.disable_mqv** - setting this property to true will disable support for EC MQV in the provider.
- **org.bouncycastle.pkcs1.not_strict** - some other providers of cryptography services fail to produce PKCS1 encoded block that are the correct length. Setting this property to true will relax the conformance check on the block length.

## 4.0 Specifications

- clean room implementation of the JCE API
- light-weight cryptographic API consisting of support for
  - BlockCipher
  - BufferedBlockCipher
  - AsymmetricBlockCipher
  - BufferedAsymmetricBlockCipher
  - StreamCipher
  - BufferedStreamCipher
  - KeyAgreement
  - IESCipher
  - Digest
  - Mac
  - PBE
  - Signers
- JCE compatible framework for a Bouncy Castle provider "BC".
- JCE compatible framework for a Bouncy Castle post-quantum provider "BCPQC".

## 5.0 Light-weight API

This API has been specifically developed for those circumstances where the rich API and integration requirements of the JCE are not required.

However as a result, the light-weight API requires more effort and understanding on the part of a developer to initialise and utilise the algorithms.

### 5.1 Example

To utilise the light-weight API in a program, the fundamentals are as follows;


        /*
         * This will use a supplied key, and encrypt the data
         * This is the equivalent of DES/CBC/PKCS5Padding
         */
        BlockCipher engine = new DESEngine();
        BufferedBlockCipher cipher = new PaddedBlockCipher(new CBCCipher(engine));

        byte[] key = keyString.getBytes();
        byte[] input = inputString.getBytes();

        cipher.init(true, new KeyParameter(key));

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        
        int outputLen = cipher.processBytes(input, 0, input.length, cipherText, 0);
        try
        {
            cipher.doFinal(cipherText, outputLen);
        }
        catch (CryptoException ce)
        {
            System.err.println(ce);
            System.exit(1);
        }

### 5.2 Algorithms

The light-weight API has built in support for the following:

#### Symmetric (Block)

The base interface is **BlockCipher** and has the following implementations which match the modes the block cipher can be operated in.

| Name                      | Constructor                       | Notes                                     |
|---------------------------|-----------------------------------|-------------------------------------------|
| **BufferedBlockCipher**   | BlockCipher                       |                                           |
| **CBCBlockCipher**        | BlockCipher                       |                                           |
| **CFBBlockCipher**        | BlockCipher, block size (in bits) |                                           |
| **GCFBlockCipher**        | BlockCipher                       | GOST CFB mode with CryptoPro key meshing. |
| **EAXBlockCipher**        | BlockCipher                       |                                           |
| **OCBBlockCipher**        | BlockCipher                       |                                           |
| **OFBBlockCipher**        | BlockCipher, block size (in bits) |                                           |
| **SICBlockCipher**        | BlockCipher, block size (in bits) | Also known as CTR mode                    |
| **KCTRBlockCipher**       | BlockCipher, block size (in bits) | DSTU7624 CTR mode                         |
| **OpenPGPCFBBlockCipher** | BlockCipher                       |                                           |
| **GOFBBlockCipher**       | BlockCipher                       | GOST OFB mode                             |

The base interface for AEAD (Authenticated Encryption Associated Data) modes is **AEADBlockCipher** and has the following implemenations.

| Name                  | Constructor | Notes                                               |
|-----------------------|-------------|-----------------------------------------------------|
| **CCMBlockCipher**    | BlockCipher | Packet mode - requires all data up front.           |
| **EAXBlockCipher**    | BlockCipher |                                                     |
| **CCMBlockCipher**    | BlockCipher | Packet mode - requires all data up front.           |
| **GCMBlockCipher**    | BlockCipher | Packet mode - NIST SP 800-38D.                      |
| **GCMSIVBlockCipher** | BlockCipher | Packet mode - RFC 8452.                             |
| **KCCMBlockCipher**   | BlockCipher | DSTU 7624 Packet mode - requires all data up front. |
| **OCBBlockCipher**    | BlockCipher |                                                     |
| **ChaCha20Poly1305**  | AEADCipher  |                                                     |

**BufferedBlockCipher** has a further sub-classes

| Name                          | Constructor | Notes                                                                  |
|-------------------------------|-------------|------------------------------------------------------------------------|
| **PaddedBufferedBlockCipher** | BlockCipher | a buffered block cipher that can use padding - default PKCS5/7 padding |
| **CTSBlockCipher**            | BlockCipher | Cipher Text Stealing                                                   |
| **NISTCTSBlockCipher**        | BlockCipher | Cipher Text Stealing - NIST mode set.                                  |

The following paddings can be used with the PaddedBufferedBlockCipher.

| Name              | Description                              |
|-------------------|------------------------------------------|
| PKCS7Padding      | PKCS7/PKCS5 padding                      |
| ISO10126d2Padding | ISO 10126-2 padding                      |
| X932Padding       | X9.23 padding                            |
| ISO7816d4Padding  | ISO 7816-4 padding (ISO 9797-1 scheme 2) |
| ZeroBytePadding   | Pad with Zeros (not recommended)         |

The following cipher engines are implemented that can be used with the above modes.

| Name                    | KeySizes (in bits) | Block Size                                  | Notes                                         |
|-------------------------|--------------------|---------------------------------------------|-----------------------------------------------|
| **AESEngine**           | 0 .. 256           | 128 bit                                     |                                               |
| **AESWrapEngine**       | 0 .. 256           | 128 bit                                     | Implements FIPS AES key wrapping              |
| **AESWrapPadEngine**    | 0 .. 256           | 128 bit                                     | Implements RFC 5649 key wrapping with padding |
| **AsconEngine**         | 128                | 128 bit                                     | AEAD Cipher                                   |
| **ARIAEngine**          | 128, 192, 256      | 128 bit                                     |                                               |
| **ARIAWrapEngine**      | 128, 192, 256      | 128 bit                                     | RFC 3394 style key wrapping                   |
| **BlowfishEngine**      | 0 .. 448           | 64 bit                                      |                                               |
| **CamelliaEngine**      | 128, 192, 256      | 128 bit                                     |                                               |
| **CamelliaWrapEngine**  | 128, 192, 256      | 128 bit                                     |                                               |
| **CAST5Engine**         | 0 .. 128           | 64 bit                                      |                                               |
| **CAST6Engine**         | 0 .. 256           | 128 bit                                     |                                               |
| **DESEngine**           | 64                 | 64 bit                                      |                                               |
| **DESedeEngine**        | 128, 192           | 64 bit                                      |                                               |
| **DESedeWrapEngine**    | 128, 192           | 64 bit                                      | Implements Draft IETF DESede key wrapping     |
| **DSTU7624Engine**      | 128, 256, 512      | 128/256/512 bit                             | DSTU7624 Block Cipher                         |
| **DSTU7624WrapEngine**  | 128, 256, 512      | 128/256/512 bit                             | DSTU7624 key wrapper                          |
| **ElephantEngine**      | 128                | 128 bit                                     | AEAD Cipher                                   |
| **GiftCofbEngine**      | 128                | 128 bit                                     | AEAD Cipher                                   |
| **GOST28147Engine**     | 256                | 64 bit                                      | Has a range of S-boxes                        |
| **GOST3412_2015Engine** | 256                | 128 bit                                     |                                               |
| **IDEAEngine**          | 128                | 64 bit                                      |                                               |
| **ISAPEngine**          | 128                | 128 bit                                     | AEAD Cipher                                   |
| **LEAEngine**           | 128                | 128/192/256 bit                             |                                               |
| **NoekeonEngine**       | 128                | 128 bit                                     |                                               |
| **PhotonBeetleEngine**  | 128                | 128 bit                                     | AEAD Cipher                                   |
| **RC2Engine**           | 0 .. 1024          | 64 bit                                      |                                               |
| **RC532Engine**         | 0 .. 128           | 64 bit                                      | Uses a 32 bit word                            |
| **RC564Engine**         | 0 .. 128           | 128 bit                                     | Uses a 64 bit word                            |
| **RC6Engine**           | 0 .. 256           | 128 bit                                     |                                               |
| **RijndaelEngine**      | 0 .. 256           | 128 bit, 160 bit, 192 bit, 224 bit, 256 bit |                                               |
| **RomulusEngine**       | 128                | 128 bit                                     | AEAD Cipher                                   |
| **SEEDEngine**          | 128                | 128 bit                                     |                                               |
| **SEEDWrapEngine**      | 128                | 128 bit                                     |                                               |
| **Shacal2Engine**       | 512                | 256 bit                                     |                                               |
| **SerpentEngine**       | 128, 192, 256      | 128 bit                                     |                                               |
| **SkipjackEngine**      | 0 .. 128           | 64 bit                                      |                                               |
| **SM4Engine**           | 128                | 128 bit                                     |                                               |
| **SparkleEngine**       | 128                | 128 bit                                     | AEAD Cipher                                   |
| **TEAEngine**           | 128                | 64 bit                                      |                                               |
| **ThreefishEngine**     | 256/512/1024       | 256 bit/512 bit/1024 bit                    | Tweakable block cipher                        |
| **TwofishEngine**       | 128, 192, 256      | 128 bit                                     |                                               |
| **XoodyakEngine**       | 128                | 128 bit                                     | AEAD Cipher                                   |
| **XTEAEngine**          | 128                | 64 bit                                      |                                               |

The following additional key wrapping algorithms are also available: RFC3211WrapEngine, RFC3394WrapEngine, and RFC5649WrapEngine.

#### Symmetric (Stream)

The base interface is **StreamCipher** and has the following implementations which match the modes the stream cipher can be operated in.

| Name                  | Constructor | Notes |
|-----------------------|-------------|-------|
| **BlockStreamCipher** | BlockCipher |       |

The following cipher engines are implemented that can be used with the above modes.

| Name                 | KeySizes (in bits) | Notes                                         |
|----------------------|--------------------|-----------------------------------------------|
| **RC4Engine**        | 40 .. 2048         |                                               |
| **HC128Engine**      | 128                |                                               |
| **HC256Engine**      | 256                |                                               |
| **ChaChaEngine**     | 128/256            | 64 bit IV                                     |
| **ChaCha7539Engine** | 256                | 96 bit IV, the RFC 7539/8439 form of ChaCha20 |
| **Salsa20Engine**    | 128/256            | 64 bit IV                                     |
| **XSalsa20Engine**   | 256                | 192 bit IV                                    |
| **XChaCha20Engine**  | 256                | 192 bit IV                                    |
| **ISAACEngine**      | 32 .. 8192         |                                               |
| **VMPCEngine**       | 8 .. 6144          |                                               |
| **VMPCKSA3Engine**   | 8 .. 6144          |                                               |
| **Grainv1Engine**    | 80                 | 64 bit IV                                     |
| **Grain128Engine**   | 128                | 96 bit IV                                     |
| **Zuc128Engine**     | 128                | 128 bit IV                                    |
| **Zuc256Engine**     | 256                | 200 bit IV                                    |

#### Block Asymmetric

The base interface is **AsymmetricBlockCipher** and has the following implementations which match the modes the cipher can be operated in.

| Name                              | Constructor           | Notes     |
|-----------------------------------|-----------------------|-----------|
| **BufferedAsymmetricBlockCipher** | AsymmetricBlockCipher |           |
| **OAEPEncoding**                  | AsymmetricBlockCipher |           |
| **PKCS1Encoding**                 | AsymmetricBlockCipher |           |
| **ISO9796d1Encoding**             | AsymmetricBlockCipher | ISO9796-1 |

The following cipher engines are implemented that can be used with the above modes.

| Name              | KeySizes (in bits)                               | Notes |
|-------------------|--------------------------------------------------|-------|
| **RSAEngine**     | any multiple of 8 large enough for the encoding. |       |
| **ElGamalEngine** | any multiple of 8 large enough for the encoding. |       |
| **NTRUEngine**    | any multiple of 8 large enough for the encoding. |       |

The following asymmetric ciphers are also supported and allow variable block sizes:

- IESEngine
- SM2Engine

#### Digest

The base interface is **Digest** and has the following implementations

| Name                        | Output (in bits)                       | Notes                                                                                     |
|-----------------------------|----------------------------------------|-------------------------------------------------------------------------------------------|
| **AsconDigest**             | 256                                    |                                                                                           |
| **AsconXof**                | XOF                                    |                                                                                           |
| **Blake2bDigest**           | 224, 256, 384, 512                     |                                                                                           |
| **Blake2bpDigest**          | 512                                    |                                                                                           |
| **Blake2sDigest**           | 128, 160, 224, 256                     |                                                                                           |
| **Blake2spDigest**          | 256                                    |                                                                                           |
| **Blake2xsDigest**          | XOF                                    |                                                                                           |
| **Blake3Digest**            | 224, 256, 384, 512                     |                                                                                           |
| **CSHAKEDigest**            | XOF                                    | SP 800-185, based on SHAKE128/SHAKE256                                                    |
| **DSTU7564Digest**          | 256, 384, 512                          |                                                                                           |
| **ISAPDigest**              | 256                                    |                                                                                           |
| **Kangaroo**                | XOF                                    | Built on Keccak-p                                                                         |
| **KeccakDigest**            | 224, 256, 288, 384, 512                |                                                                                           |
| **MD2Digest**               | 128                                    |                                                                                           |
| **MD4Digest**               | 128                                    |                                                                                           |
| **MD5Digest**               | 128                                    |                                                                                           |
| **ParallelHash**            | XOF                                    | XOF based on cSHAKE (SP 800-185).                                                         |
| **PhotonBeetleDigest**      | 256                                    |                                                                                           |
| **RipeMD128Digest**         | 128                                    | basic RipeMD                                                                              |
| **RipeMD160Digest**         | 160                                    | enhanced version of RipeMD                                                                |
| **RipeMD256Digest**         | 256                                    | expanded version of RipeMD128                                                             |
| **RipeMD320Digest**         | 320                                    | expanded version of RipeMD160                                                             |
| **RomulusDigest**           | 256                                    |                                                                                           |
| **SHA1Digest**              | 160                                    |                                                                                           |
| **SHA224Digest**            | 224                                    | FIPS 180-2                                                                                |
| **SHA256Digest**            | 256                                    | FIPS 180-2                                                                                |
| **SHA384Digest**            | 384                                    | FIPS 180-2                                                                                |
| **SHA512Digest**            | 512                                    | FIPS 180-2                                                                                |
| **SHA512tDigest**           | SHA-512/t, any multiple of 8 up to 376 | FIPS 180-4                                                                                |
| **SHA3Digest**              | 224, 256, 384, 512                     |                                                                                           |
| **SHAKEDigest**             | 128, 256                               | cSHAKE primitive also supported.                                                          |
| **SkeinDigest**             | any byte length                        | 256 bit, 512 bit and 1024 state sizes. Additional parameterisation using SkeinParameters. |
| **SM3Digest**               | 256                                    | The SM3 Digest.                                                                           |
| **SparkleDigest**           | 256                                    |                                                                                           |
| **TigerDigest**             | 192                                    | The Tiger Digest.                                                                         |
| **TupleHash**               | XOF                                    | XOF based on cSHAKE (SP 800-185).                                                         |
| **GOST3411Digest**          | 256                                    | The GOST-3411 Digest.                                                                     |
| **GOST3411_2012_256Digest** | 256                                    | The GOST-3411-2012-256 Digest.                                                            |
| **GOST3411_2012_512Digest** | 512                                    | The GOST-3411-2012-512 Digest.                                                            |
| **WhirlpoolDigest**         | 512                                    | The Whirlpool Digest.                                                                     |
| **Haraka256Digest**         | 256                                    | Haraka V2 - 256 bit input version.                                                        |
| **Haraka512Digest**         | 256                                    | Haraka V2 - 512 bit input version.                                                        |
| **XoodyakDigest**           | 256                                    |                                                                                           |

#### MAC

The base interface is **Mac** and has the following implementations

| Name                  | Output (in bits)                                 | Notes                                                                                             |
|-----------------------|--------------------------------------------------|---------------------------------------------------------------------------------------------------|
| **Blake3Mac**         | 256 bits                                         |                                                                                                   |
| **CBCBlockCipherMac** | blocksize/2 unless specified                     |                                                                                                   |
| **CFBBlockCipherMac** | blocksize/2, in CFB 8 mode, unless specified     |                                                                                                   |
| **CMac**              | 24 to cipher block size bits                     | Usable with block ciphers, NIST SP 800-38B.                                                       |
| **GMac**              | 32 to 128 bits                                   | Usable with GCM mode ciphers, defined for AES, NIST SP 800-38D.                                   |
| **KGMac**             | 32 to 128 bits                                   | GMac variant for use with KGCM mode ciphers (DSTU 7624)                                           |
| **GOST28147Mac**      | 32 bits                                          |                                                                                                   |
| **ISO9797Alg3Mac**    | multiple of 8 bits up to underlying cipher size. |                                                                                                   |
| **KMAC**              | arbitrary                                        | NIST SP 800-185, based on SHAKE128/SHAKE256                                                       |
| **HMac**              | digest length                                    |                                                                                                   |
| **DSTU7564**          | 256, 384, 512 bits                               |                                                                                                   |
| **DSTU7624**          | 128, 256, 512 bits                               |                                                                                                   |
| **Poly1305**          | 128 bits                                         | Usable with 128 bit block ciphers. Use Poly1305KeyGenerator to generate keys.                     |
| **SkeinMac**          | any byte length                                  | 256 bit, 512 bit and 1024 state size variants. Additional parameterisation using SkeinParameters. |
| **SipHash**           | 64 bits                                          |                                                                                                   |
| **SipHash128**        | 128 bits                                         |                                                                                                   |
| **VMPCMac**           | 160 bits                                         |                                                                                                   |
| **Zuc128Mac**         | 32 bits                                          |                                                                                                   |
| **Zuc256Mac**         | 32, 64, 128 bits                                 |                                                                                                   |

#### PBE and Password Hashing

The base class is **PBEParametersGenerator** and has the following sub-classes

| Name                              | Constructor | Notes                     |
|-----------------------------------|-------------|---------------------------|
| **PKCS5S1ParametersGenerator**    | Digest      |                           |
| **PKCS5S2ParametersGenerator**    |             | Uses SHA1/Hmac as defined |
| **PKCS12ParametersGenerator**     | Digest      |                           |
| **OpenSSLPBEParametersGenerator** |             | Uses MD5 as defined       |

The following password hashing schemes are supported:

| Name              | Constructor | Notes |
|-------------------|-------------|-------|
| **Argon2**        |             |       |
| **BCrypt**        |             |       |
| **OpenBSDBcyrpt** |             |       |
| **SCrypt**        |             |       |

#### IESCipher

The IES cipher is based on the one described in IEEE P1363a (draft 10), for use with either traditional Diffie-Hellman or Elliptic Curve Diffie-Hellman.

**Note:** At the moment this is still a draft, don't use it for anything that may be subject to long term storage, the key values produced may well change as the draft is finalised.

#### Commitments

The base class is **Committer** and has the following sub-classes

| Name              | Notes                                                                 |
|-------------------|-----------------------------------------------------------------------|
| **HashCommitter** | Hash commitment algorithm described in Usenix RPC MixNet Paper (2002) |

#### Key Agreement

Two versions of Diffie-Hellman key agreement are supported, the basic version, and one for use with long term public keys. Two versions of key agreement using Elliptic Curve cryptography are also supported, standard Diffie-Hellman key agreement and standard key agreement with co-factors.

Agreement using the RFC 7748 Montgomery curve functions is provided by **X25519Agreement** and **X448Agreement**, MQV and unified-model variants are available for both Diffie-Hellman and EC, and SM2 key exchange is supported by **SM2KeyExchange**. Password-authenticated key establishment is provided by the J-PAKE, EC-J-PAKE, SRP-6a, and Owl protocols in subpackages of **org.bouncycastle.crypto.agreement**.

The agreement APIs are in the **org.bouncycastle.crypto.agreement** package. Classes for generating Diffie-Hellman parameters can be found in the **org.bouncycastle.crypto.params** and **org.bouncycastle.crypto.generators** packages.

#### Key Encapsulation Mechanisms

The first non-post-quantum set use the **EncapsulatedSecretGenerator** and **EncapsulatedSecretExtractor** interfaces.

| Name      | Notes                                                                                             |
|-----------|---------------------------------------------------------------------------------------------------|
| **RSA**   | RSA-KEM from ISO 18033-2, implemented in **RSAKEMExtractor** and **RSAKEMGenerator**              |
| **ECIES** | ECIES-KEM from ISO 18033-2, implemented in **ECIESKEMExtractor** and **ECIESKEMGenerator**        |
| **SAKKE** | Sakai-Kasahara KEM from RFC 6508, implemented in **SAKKEKEMSGenerator** and **SAKKEKEMExtractor** |

The second, post-quantum set also use **EncapsulatedSecretGenerator** and **EncapsulatedSecretExtractor**.

|                      |                             |                                                                                                                    |                                                                 |
|----------------------|-----------------------------|--------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| Name                 | Security Strength (in bits) | Implementations                                                                                                    | Notes                                                           |
| **BIKE**             | 128-256.                    | **BIKEKEMGenerator**, **BIKEKEMExtractor**                                                                         | Round 4                                                         |
| **Classic McEliece** | 128-256.                    | **CMCEKEMGenerator**, **CMCEKEMExtractor**                                                                         | Round 4                                                         |
| **FrodoKEM**         | 128-256.                    | **FrodoKEMGenerator**, **FrodoKEMExtractor**                                                                       |                                                                 |
| **HQC**              | 128-256.                    | **HQCKEMGenerator**, **HQCKEMExtractor**                                                                           | Round 4                                                         |
| **ML-KEM**           | 128-256.                    | **MLKEMGenerator**, **MLKEMExtractor**                                                                             | Finalist                                                        |
| **NTRU**             | 128-256.                    | **NTRUKEMGenerator**, **NTRUKEMExtractor**                                                                         |                                                                 |
| **NTRU+**            | 128-256.                    | **NTRUPlusKEMGenerator**, **NTRUPlusKEMExtractor**                                                                 | KpqC competition                                                |
| **NTRU Prime**       | 128-256.                    | **NTRULPRimeKEMGenerator**, **NTRULPRimeKEMExtractor**<br>**SNTRUPrimeKEMGenerator**, **SNTRUPrimeKEMExtractor** |                                                                 |
| **SABER**            | 128-256.                    | **SABERKEMGenerator**, **SABERKEMExtractor**                                                                       |                                                                 |
| **X-Wing**           | 128\.                       | **XWingKEMGenerator**, **XWingKEMExtractor**                                                                       | Hybrid of X25519 and ML-KEM-768 (draft-connolly-cfrg-xwing-kem) |

The standardised versions of Classic McEliece, FrodoKEM, and ML-KEM are implemented under **org.bouncycastle.crypto.kems**; the Classic McEliece implementation there covers the parameter sets standardised in ISO/IEC 18033-2:2006/Amd 2 (including the pc/pcf plaintext-confirmation variants).

#### Signers

DSA, ECDSA, Ed25519 and Ed448 (RFC 8032), BIP-340 Schnorr, SM2, ISO-9796-2, GOST-3410-94, GOST-3410-2001, GOST-3410-2012, DSTU-4145-2002, RSA-PSS, and BLS12-381 signatures (draft-irtf-cfrg-bls-signature, with the scheme classes in **org.bouncycastle.crypto.bls**) are supported by the **org.bouncycastle.crypto.signers** package. Note: as these are light weight classes, if you need to use SHA1 or GOST-3411 (as defined in the relevant standards) you'll also need to make use of the appropriate digest class in conjunction with these. Classes for generating DSA and ECDSA parameters can be found in the **org.bouncycastle.crypto.params** and **org.bouncycastle.crypto.generators** packages. Post-quantum signature algorithms (ML-DSA, SLH-DSA, LMS/HSS, XMSS/XMSS^MT, Falcon, Mayo, Snova, and the NIST additional-signatures round candidates) are provided under **org.bouncycastle.pqc.crypto**.

### 5.4 Elliptic Curve Transforms.

The org.bouncycastle.crypto.ec package contains implementations for a variety of EC cryptographic transforms such as EC ElGamal.

### 5.5 TLS/DTLS

The org.bouncycastle.crypto.tls package contains implementations for TLS 1.1, 1.2 and DTLS 1.0, 1.2.

### 5.6 Deterministic Random Bit Generators (DRBG) and SecureRandom wrappers

The org.bouncycastle.crypto.prng package contains implementations for a variety of bit generators including those from SP 800-90A and X9.31, as well as builders for SecureRandom objects based around them.

### 5.7 ASN.1 package

The light-weight API has direct interfaces into a package capable of reading and writing DER-encoded ASN.1 objects and for the generation of X.509 V3 certificate objects and PKCS12 files. BER InputStream and OutputStream classes are provided as well.

## 6.0 Bouncy Castle Provider

The Bouncy Castle provider is a JCE compliant provider that is a wrapper built on top of the light-weight API. The main provider is referred to with the name "BC", the post quantum provider is indicated by "BCPQC".

The advantage for writing application code that uses the provider interface to cryptographic algorithms is that the actual provider used can be selected at run time. This is extremely valuable for applications that may wish to make use of a provider that has underlying hardware for cryptographic computation, or where an application may have been developed in an environment with cryptographic export controls.

### 6.1 Example

To utilise the JCE provider in a program, the fundamentals are as follows;


        /*
         * This will generate a random key, and encrypt the data
         */
        Key     key;
        KeyGenerator    keyGen;
        Cipher      encrypt;

        Security.addProvider(new BouncyCastleProvider());

        try
        {
            // "BC" is the name of the BouncyCastle provider
            keyGen = KeyGenerator.getInstance("DES", "BC");
            keyGen.init(new SecureRandom());

            key = keyGen.generateKey();

            encrypt = Cipher.getInstance("DES/CBC/PKCS5Padding", "BC");
        }
        catch (Exception e)
        {
            System.err.println(e);
            System.exit(1);
        }

        encrypt.init(Cipher.ENCRYPT_MODE, key);

        bOut = new ByteArrayOutputStream();
        cOut = new CipherOutputStream(bOut, encrypt);

        cOut.write("plaintext".getBytes());
        cOut.close();

        // bOut now contains the cipher text

The provider can also be configured as part of your environment via static registration by adding an entry to the java.security properties file (found in \$JAVA_HOME/jre/lib/security/java.security, where \$JAVA_HOME is the location of your JDK/JRE distribution). You'll find detailed instructions in the file but basically it comes down to adding a line:


        security.provider.<n>=org.bouncycastle.jce.provider.BouncyCastleProvider

Where \<n\> is the preference you want the provider at (1 being the most prefered).

Where you put the jar is up to mostly up to you, although with jdk1.3 and jdk1.4 the best (and in some cases only) place to have it is in \$JAVA_HOME/jre/lib/ext. Note: under Windows there will normally be a JRE and a JDK install of Java if you think you have installed it correctly and it still doesn't work chances are you have added the provider to the installation not being used.

**Note**: with JDK 1.4 and later you will need to have installed the unrestricted policy files to take full advantage of the provider. If you do not install the policy files you are likely to get something like the following:

            java.lang.SecurityException: Unsupported keysize or algorithm parameters
                    at javax.crypto.Cipher.init(DashoA6275)

The policy files can be found at the same place you downloaded the JDK.

### 6.2 Algorithms

#### Symmetric (Block)

Modes:

- ECB
- CBC
- OFB(n)
- CFB(n)
- SIC (also known as CTR)
- OpenPGPCFB
- CTS (equivalent to CBC/WithCTS)
- FF1
- FF3-1
- GOFB
- GCFB
- CCM (AEAD)
- EAX (AEAD)
- GCM (AEAD)
- GCM-SIV (AEAD)
- OCB (AEAD)

Where *(n)* is a multiple of 8 that gives the blocksize in bits, eg, OFB8. Note that OFB and CFB mode can be used with plain text that is not an exact multiple of the block size if NoPadding has been specified.

All *AEAD* (Authenticated Encryption Associated Data) modes support Additional Authentication Data (AAD) using the `Cipher.updateAAD()` methods added in Java SE 7.  
On Java 7 and later, AEAD modes will throw `javax.crypto.AEADBadTagException` on an authentication failure. On earlier version of Java, `javax.crypto.BadPaddingException` is thrown.

Padding Schemes:

- No padding
- PKCS5/7
- ISO10126/ISO10126-2
- ISO7816-4/ISO9797-1
- X9.23/X923
- TBC
- ZeroByte
- withCTS (if used with ECB mode)

When placed together this gives a specification for an algorithm as;

- DES/CBC/X9.23Padding
- DES/OFB8/NoPadding
- IDEA/CBC/ISO10126Padding
- IDEA/CBC/ISO7816-4Padding
- SKIPJACK/ECB/PKCS7Padding
- DES/ECB/WithCTS

Note: default key sizes are in bold.

| Name           | KeySizes (in bits)      | Block Size       | Notes                                                                   |
|----------------|-------------------------|------------------|-------------------------------------------------------------------------|
| AES            | 0 .. 256 **(192)**      | 128 bit          |                                                                         |
| AESWrap        | 0 .. 256 **(192)**      | 128 bit          | A FIPS AES key wrapper                                                  |
| ARIA           | 0 .. 256 **(192)**      | 128 bit          |                                                                         |
| ARIAWrap       | 0 .. 256 **(192)**      | 128 bit          | An ARIA key wrapper (based on RFC 5649)                                 |
| Blowfish       | 0 .. 448 **(448)**      | 64 bit           |                                                                         |
| Camellia       | 128, 192, 256           | 128 bit          |                                                                         |
| CamelliaWrap   | 128, 192, 256           | 128 bit          |                                                                         |
| CAST5          | 0 .. 128**(128)**       | 64 bit           |                                                                         |
| CAST6          | 0 .. 256**(256)**       | 128 bit          |                                                                         |
| DES            | 64                      | 64 bit           |                                                                         |
| DESede         | 128, 192                | 64 bit           |                                                                         |
| DESedeWrap     | 128, 192                | 128 bit          | A Draft IETF DESede key wrapper                                         |
| DSTU7624       | 128, 256, 512           | 128/256/512 bit  | DSTU7624 Block Cipher                                                   |
| DSTU7624Wrap   | 128, 256, 512           | 128/256/512 bit  | DSTU7624 key wrapper                                                    |
| GCM            | 128, 192, 256**(192)**  | AEAD Mode Cipher | Galois/Counter Mode, as defined in NIST Special Publication SP 800-38D. |
| GOST28147      | 256                     | 64 bit           |                                                                         |
| GOST3412-2015  | 256                     | 128 bit          |                                                                         |
| IDEA           | 128 **(128)**           | 64 bit           |                                                                         |
| LEA            | 128, 192, 256           | 128 bit          |                                                                         |
| Noekeon        | 128**(128)**            | 128 bit          |                                                                         |
| RC2            | 0 .. 1024 **(128)**     | 64 bit           |                                                                         |
| RC5            | 0 .. 128 **(128)**      | 64 bit           | Uses a 32 bit word                                                      |
| RC5-64         | 0 .. 256 **(256)**      | 128 bit          | Uses a 64 bit word                                                      |
| RC6            | 0 .. 256 **(128)**      | 128 bit          |                                                                         |
| Rijndael       | 0 .. 256 **(192)**      | 128 bit          |                                                                         |
| SEED           | 128**(128)**            | 128 bit          |                                                                         |
| SEEDWrap       | 128**(128)**            | 128 bit          |                                                                         |
| Serpent        | 128, 192, 256 **(256)** | 128 bit          |                                                                         |
| Shacal2        | 128 .. 512              | 256 bit          |                                                                         |
| Skipjack       | 0 .. 128 **(128)**      | 64 bit           |                                                                         |
| SM4            | 128**(128)**            | 128 bit          |                                                                         |
| TEA            | 128 **(128)**           | 64 bit           |                                                                         |
| Threefish-256  | 256                     | 256 bit          |                                                                         |
| Threefish-512  | 512                     | 512 bit          |                                                                         |
| Threefish-1024 | 1024                    | 1024 bit         |                                                                         |
| Twofish        | 128, 192, 256 **(256)** | 128 bit          |                                                                         |
| XTEA           | 128 **(128)**           | 64 bit           |                                                                         |

#### Symmetric (Stream)

Note: default key sizes are in bold.

| Name         | KeySizes (in bits)        | Notes                                         |
|--------------|---------------------------|-----------------------------------------------|
| RC4          | 40 .. 2048 bits **(128)** |                                               |
| HC128        | \(128\)                   |                                               |
| HC256        | \(256\)                   |                                               |
| ChaCha       | **128**/256               | 64 bit IV                                     |
| ChaCha7539   | 256                       | 96 bit IV, the RFC 7539/8439 form of ChaCha20 |
| Salsa20      | **128**/256               | 64 bit IV                                     |
| XSalsa20     | 256                       | 192 bit IV                                    |
| XChaCha20    | 256                       | 192 bit IV                                    |
| VMPC         | 128/6144**(128)**         |                                               |
| VMPC-KSA3    | 128/6144**(128)**         |                                               |
| Grainv1      | 80                        | 64 bit IV                                     |
| Grain128     | 128                       | 96 bit IV                                     |
| Grain128AEAD | 128                       | 96 bit IV                                     |
| Zuc128       | 128                       | 128 bit IV                                    |
| Zuc256       | 256                       | 200 bit IV                                    |

#### Block Asymmetric

Encoding:

- OAEP - Optimal Asymmetric Encryption Padding
- PCKS1 - PKCS v1.5 Padding
- ISO9796-1 - ISO9796-1 edition 1 Padding

Note: except as indicated in PKCS 1v2 we recommend you use OAEP, as mandated in X9.44.

When placed together with RSA this gives a specification for an algorithm as;

- RSA/NONE/NoPadding
- RSA/NONE/PKCS1Padding
- RSA/NONE/OAEPWithMD5AndMGF1Padding
- RSA/NONE/OAEPWithSHA1AndMGF1Padding
- RSA/NONE/OAEPWithSHA224AndMGF1Padding
- RSA/NONE/OAEPWithSHA256AndMGF1Padding
- RSA/NONE/OAEPWithSHA384AndMGF1Padding
- RSA/NONE/OAEPWithSHA512AndMGF1Padding
- RSA/NONE/OAEPWithSHA3-224AndMGF1Padding
- RSA/NONE/OAEPWithSHA3-256AndMGF1Padding
- RSA/NONE/OAEPWithSHA3-384AndMGF1Padding
- RSA/NONE/OAEPWithSHA3-512AndMGF1Padding
- RSA/NONE/ISO9796-1Padding

| Name    | KeySizes (in bits)                                               | Notes |
|---------|------------------------------------------------------------------|-------|
| RSA     | any multiple of 8 bits large enough for the encryption**(2048)** |       |
| ElGamal | any multiple of 8 bits large enough for the encryption**(1024)** |       |

#### Key Agreement

Diffie-Hellman key agreement is supported using the "DH", "DHU" (Diffie-Hellman Unified", "ECDH", "ECCDH" (EC Cofactor DH), "ECKAEG" (BSI EC KAEG key agreement"), "ECMQV" and "ECCDHU" (EC Cofactor DH Unified) key agreement instances and their variations. Key exchange, which also uses the KeyAgreement API is supported by "NH" (the NewHope algorithm (BCPQC)). SM2 key exchange is currently supported in the lightweight API.

Support is provided for the standard SEC algorithm set for EC. Names appear in the form of [Agreement]with[KDF PRF Digest][KDF type]. For example:

- "ECCDHwithSHA256KDF" which represents EC cofactor DH using the X9.63 KDF with SHA256 as the PRF
- "ECMQVwithSHA1CKDF" which represents EC MQV using the concetantion KDF with SHA1 as the PRF

Note: with basic "DH" only the basic algorithm fits in with the JCE API, if you're using long-term public keys you may want to look at the light-weight API, there are also additional JCE support classes for UserKeyingMaterial and MQVParameters in the **org.bouncycastle.jcajce.spec** package.

#### Key Encapsulation Mechanisms

| Name                        | ParameterSpec Class                               | Notes                                                                                                                                |
|-----------------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **CMCE**                    | CMCEParameterSpec                                 | Classic McEliece; the BC provider implements the ISO/IEC 18033-2:2006/Amd 2 parameter sets, the BCPQC provider the NIST round-3 sets |
| **Frodo**                   | FrodoParameterSpec                                | FrodoKEM (NIST Alternate Candidate)                                                                                                  |
| **SABER**                   | SABERParameterSpec                                | SABER (NIST Finalist, BCPQC)                                                                                                         |
| **ML-KEM**                  | MLKEMParameterSpec                                | FIPS 203 Module-Lattice KEM (BC provider)                                                                                            |
| **BIKE**                    | BIKEParameterSpec                                 | NIST Round 4 candidate (BCPQC)                                                                                                       |
| **HQC**                     | HQCParameterSpec                                  | NIST Round 4 candidate (BCPQC)                                                                                                       |
| **NTRU**                    | NTRUParameterSpec                                 | (BCPQC)                                                                                                                              |
| **NTRULPRime / SNTRUPrime** | NTRULPRimeParameterSpec / SNTRUPrimeParameterSpec | NTRU Prime (BCPQC)                                                                                                                   |
| **NTRU+**                   | NTRUPlusParameterSpec                             | KpqC competition (BCPQC)                                                                                                             |
| **Composite ML-KEM**        |                                                   | ML-KEM-768/1024 combined with RSA-OAEP, ECDH, X25519 or X448 per draft-ietf-lamps-pq-composite-kem (BC provider)                     |

If used for key wrapping via the Cipher class, you will also need to make use of the KEMParameterSpec class to specify a symmetric wrapping algorithm.

If access to the shared secret is required, KeyGenerator implementations can also be used in conjuction with the KEMGenerateSpec and the KEMExtractSpec which return the shared secret directly.

#### ECIES

An implementation of ECIES (stream mode) as described in IEEE P 1363a. This now based more formally on Victor Shoup's paper and should be compatible with the implementation in Crypto++ (version 6 onwards).

#### Digest

| Name              | Output (in bits)             | Notes                         |
|-------------------|------------------------------|-------------------------------|
| Blake2b-160       | 160                          |                               |
| Blake2b-256       | 256                          |                               |
| Blake2b-384       | 384                          |                               |
| Blake2b-512       | 512                          |                               |
| Blake2s-128       | 128                          |                               |
| Blake2s-160       | 160                          |                               |
| Blake2s-224       | 224                          |                               |
| Blake2s-256       | 256                          |                               |
| Blake3-256        | 256                          |                               |
| DSTU7564-256      | 256                          |                               |
| DSTU7564-384      | 384                          |                               |
| DSTU7564-512      | 512                          |                               |
| GOST3411          | 256                          |                               |
| GOST3411-2012-256 | 256                          |                               |
| GOST3411-2012-512 | 512                          |                               |
| Haraka-256        | 256                          |                               |
| Haraka-512        | 256                          |                               |
| Keccak-224        | 224                          |                               |
| Keccak-288        | 288                          |                               |
| Keccak-256        | 256                          |                               |
| Keccak-384        | 384                          |                               |
| Keccak-512        | 512                          |                               |
| MD2               | 128                          |                               |
| MD4               | 128                          |                               |
| MD5               | 128                          |                               |
| RipeMD128         | 128                          | basic RipeMD                  |
| RipeMD160         | 160                          | enhanced version of RipeMD    |
| RipeMD256         | 256                          | expanded version of RipeMD128 |
| RipeMD320         | 320                          | expanded version of RipeMD160 |
| SHA1              | 160                          |                               |
| SHA-224           | 224                          | FIPS 180-2                    |
| SHA-256           | 256                          | FIPS 180-2                    |
| SHA-384           | 384                          | FIPS 180-2                    |
| SHA-512           | 512                          | FIPS 180-2                    |
| SHA3-224          | 224                          | FIPS 202                      |
| SHA3-256          | 256                          | FIPS 202                      |
| SHA3-384          | 384                          | FIPS 202                      |
| SHA3-512          | 512                          | FIPS 202                      |
| Skein-256-\*      | 128, 160, 224, 256           | e.g. Skein-256-160            |
| Skein-512-\*      | 128, 160, 224, 256, 384, 512 | e.g. Skein-512-256            |
| Skein-1024-\*     | 384, 512, 1024               | e.g. Skein-1024-1024          |
| SM3               | 256                          |                               |
| Tiger             | 192                          |                               |
| Whirlpool         | 512                          |                               |

#### MAC

| Name                                                              | Output (in bits)                               | Notes                                                                          |
|-------------------------------------------------------------------|------------------------------------------------|--------------------------------------------------------------------------------|
| Any MAC based on a block cipher, CBC (the default) and CFB modes. | half the cipher's block size (usually 32 bits) |                                                                                |
| \*-GMAC                                                           | 32 to 128 bits                                 | Usable with GCM mode ciphers, defined for AES, NIST SP 800-38D. e.g. AES-GMAC. |
| VMPC-MAC                                                          | 128                                            |                                                                                |
| HMac-GOST3411                                                     | 256                                            |                                                                                |
| HMac-GOST3411-2012-256                                            | 256                                            |                                                                                |
| HMac-GOST3411-2012-512                                            | 512                                            |                                                                                |
| HMac-KECCAK224                                                    | 224                                            |                                                                                |
| HMac-KECCAK256                                                    | 256                                            |                                                                                |
| HMac-KECCAK288                                                    | 288                                            |                                                                                |
| HMac-KECCAK384                                                    | 384                                            |                                                                                |
| HMac-KECCAK512                                                    | 512                                            |                                                                                |
| HMac-MD2                                                          | 128                                            |                                                                                |
| HMac-MD4                                                          | 128                                            |                                                                                |
| HMac-MD5                                                          | 128                                            |                                                                                |
| HMac-RipeMD128                                                    | 128                                            |                                                                                |
| HMac-RipeMD160                                                    | 160                                            |                                                                                |
| HMac-SHA1                                                         | 160                                            |                                                                                |
| HMac-SHA224                                                       | 224                                            |                                                                                |
| HMac-SHA256                                                       | 256                                            |                                                                                |
| HMac-SHA384                                                       | 384                                            |                                                                                |
| HMac-SHA512                                                       | 512                                            |                                                                                |
| HMac-SHA3-224                                                     | 224                                            |                                                                                |
| HMac-SHA3-256                                                     | 256                                            |                                                                                |
| HMac-SHA3-384                                                     | 384                                            |                                                                                |
| HMac-SHA3-512                                                     | 512                                            |                                                                                |
| HMAC-Skein-256-\*                                                 | 128, 160, 224, 256                             | e.g. HMAC-Skein-256-160                                                        |
| HMAC-Skein-512-\*                                                 | 128, 160, 224, 256, 384, 512                   | e.g. HMAC-Skein-512-256                                                        |
| HMAC-Skein-1024-\*                                                | 384, 512, 1024                                 | e.g. HMAC-Skein-1024-1024                                                      |
| Siphash-2-4 (SipHash)                                             | 64                                             |                                                                                |
| Siphash-4-8                                                       | 64                                             |                                                                                |
| Siphash128-2-4 (SipHash128)                                       | 128                                            |                                                                                |
| Skein-MAC-256-\*                                                  | 128, 160, 224, 256                             | e.g. Skein-MAC-256-160                                                         |
| Skein-MAC-512-\*                                                  | 128, 160, 224, 256, 384, 512                   | e.g. Skein-MAC-512-256                                                         |
| Skein-MAC-1024-\*                                                 | 384, 512, 1024                                 | e.g. Skein-MAC-1024-1024                                                       |
| HMac-Tiger                                                        | 192                                            |                                                                                |
| Poly1305-\*                                                       | 128                                            | Defined for recent 128 bit block ciphers, e.g. Poly1305-AES, Poly1305-Serpent  |
| ZUC-128                                                           | 32                                             |                                                                                |
| ZUC-256-32                                                        | 32                                             |                                                                                |
| ZUC-256-64                                                        | 64                                             |                                                                                |
| ZUC-256-128                                                       | 128                                            |                                                                                |

Examples:

- DESMac
- DESMac/CFB8
- DESedeMac
- DESedeMac/CFB8
- DESedeMac64
- SKIPJACKMac
- SKIPJACKMac/CFB8
- IDEAMac
- IDEAMac/CFB8
- RC2Mac
- RC2Mac/CFB8
- RC5Mac
- RC5Mac/CFB8
- ISO9797ALG3Mac

#### Signature Algorithms

Schemes:

- DSTU4145
- Ed25519
- Ed448
- GOST3411withGOST3410 (GOST3411withGOST3410-94)
- GOST3411withECGOST3410 (GOST3411withGOST3410-2001)
- MD2withRSA
- MD5withRSA
- SHA1withRSA
- RIPEMD128withRSA
- RIPEMD160withRSA
- RIPEMD160withDSA
- RIPEMD160withECDSA
- RIPEMD256withRSA
- SHA1withDSA
- SHA224withDSA
- SHA256withDSA
- SHA384withDSA
- SHA512withDSA
- SHA3-224withDSA
- SHA3-256withDSA
- SHA3-384withDSA
- SHA3-512withDSA
- SHA1withDDSA
- SHA224withDDSA
- SHA256withDDSA
- SHA384withDDSA
- SHA512withDDSA
- SHA3-224withDDSA
- SHA3-256withDDSA
- SHA3-384withDDSA
- SHA3-512withDDSA
- NONEwithDSA
- SHA1withDetECDSA
- SHA224withECDDSA
- SHA256withECDDSA
- SHA384withECDDSA
- SHA512withECDDSA
- SHA1withECDSA
- NONEwithECDSA
- SHA224withECDSA
- SHA256withECDSA
- SHA384withECDSA
- SHA512withECDSA
- SHA3-224withECDSA
- SHA3-256withECDSA
- SHA3-384withECDSA
- SHA3-512withECDSA
- SHAKE128withECDSA
- SHAKE256withECDSA
- SHA1withPLAIN-ECDSA
- SHA224withPLAIN-ECDSA
- SHA256withPLAIN-ECDSA
- SHA384withPLAIN-ECDSA
- SHA512withPLAIN-ECDSA
- SHA3-224withPLAIN-ECDSA
- SHA3-256withPLAIN-ECDSA
- SHA3-384withPLAIN-ECDSA
- SHA3-512withPLAIN-ECDSA
- SHA1withECNR
- SHA224withECNR
- SHA256withECNR
- SHA384withECNR
- SHA512withECNR
- SHA224withRSA
- SHA256withRSA
- SHA384withRSA
- SHA512withRSA
- SHA512(224)withRSA
- SHA512(256)withRSA
- SHA3-224withRSA
- SHA3-256withRSA
- SHA3-384withRSA
- SHA3-512withRSA
- SHA1withRSAandMGF1
- SHA256withRSAandMGF1
- SHA384withRSAandMGF1
- SHA512withRSAandMGF1
- SHA512(224)withRSAandMGF1
- SHA512(256)withRSAandMGF1
- SHA1withRSA/ISO9796-2
- RIPEMD160withRSA/ISO9796-2
- SHA1withRSA/X9.31
- SHA224withRSA/X9.31
- SHA256withRSA/X9.31
- SHA384withRSA/X9.31
- SHA512withRSA/X9.31
- SHA512(224)withRSA/X9.31
- SHA512(256)withRSA/X9.31
- RIPEMD128withRSA/X9.31
- RIPEMD160withRSA/X9.31
- WHIRLPOOLwithRSA/X9.31
- SHA512withSPHINCS256 (BCPQC)
- SHA3-512withSPHINCS256 (BCPQC)
- SHA256withSM2
- SM3withSM2
- LMS
- ML-DSA
- HASH-ML-DSA (pre-hash ML-DSA, also available as SHA512withMLDSA)
- Falcon
- SLH-DSA
- XMSS-SHA256
- XMSS-SHA512
- XMSS-SHAKE128
- XMSS-SHAKE256
- XMSSMT-SHA256
- XMSSMT-SHA512
- XMSSMT-SHAKE128
- XMSSMT-SHAKE256
- SHA256withXMSS-SHA256
- SHA512withXMSS-SHA512
- SHAKE128withXMSS-SHAKE128
- SHAKE256withXMSS-SHAKE256
- SHA256withXMSSMT-SHA256
- SHA512withXMSSMT-SHA512
- SHAKE128withXMSSMT-SHAKE128
- SHAKE256withXMSSMT-SHAKE256
- MLDSA44
- MLDSA65
- MLDSA87
- MLDSA44-ECDSA-P256-SHA256
- MLDSA44-Ed25519-SHA512
- MLDSA44-RSA2048-PKCS15-SHA256
- MLDSA44-RSA2048-PSS-SHA256
- MLDSA65-ECDSA-P256-SHA512
- MLDSA65-ECDSA-brainpoolP256r1-SHA512
- MLDSA65-ECDSA-P384-SHA512
- MLDSA65-Ed25519-SHA512
- MLDSA65-RSA3072-PKCS15-SHA512
- MLDSA65-RSA3072-PSS-SHA512
- MLDSA65-RSA4096-PKCS15-SHA512
- MLDSA65-RSA4096-PSS-SHA512
- MLDSA87-ECDSA-P384-SHA512
- MLDSA87-ECDSA-brainpoolP384r1-SHA512
- MLDSA87-ECDSA-P521-SHA512
- MLDSA87-Ed448-SHAKE256
- MLDSA87-RSA3072-PSS-SHA512
- MLDSA87-RSA4096-PSS-SHA512
- SLH-DSA-SHA2-128F
- SLH-DSA-SHA2-128S
- SLH-DSA-SHA2-192F
- SLH-DSA-SHA2-192S
- SLH-DSA-SHA2-256F
- SLH-DSA-SHA2-256S
- SLH-DSA-SHAKE-128F
- SLH-DSA-SHAKE-128S
- SLH-DSA-SHAKE-192F
- SLH-DSA-SHAKE-192S
- SLH-DSA-SHAKE-256F
- SLH-DSA-SHAKE-256S
- SLH-DSA-SHA2-128F-WITH-SHA256
- SLH-DSA-SHA2-128S-WITH-SHA256
- SLH-DSA-SHA2-192F-WITH-SHA512
- SLH-DSA-SHA2-192S-WITH-SHA512
- SLH-DSA-SHA2-256F-WITH-SHA512
- SLH-DSA-SHA2-256S-WITH-SHA512
- SLH-DSA-SHAKE-128F-WITH-SHAKE128
- SLH-DSA-SHAKE-128S-WITH-SHAKE128
- SLH-DSA-SHAKE-192F-WITH-SHAKE256
- SLH-DSA-SHAKE-192S-WITH-SHAKE256
- SLH-DSA-SHAKE-256F-WITH-SHAKE256
- SLH-DSA-SHAKE-256S-WITH-SHAKE256

#### Password Hashing and PBE

Schemes:

- BCrypt
- OpenBSDBcyrpt
- SCrypt
- Argon2 (as SecretKeyFactory "ARGON2", RFC 9106, parameters supplied via Argon2KeySpec)
- PKCS5S1, any Digest, any symmetric Cipher, ASCII
- PKCS5S2, any HMac, any symmetric Cipher, ASCII, UTF8
- PKCS12, any Digest, any symmetric Cipher, Unicode

Defined in Bouncy Castle JCE Provider

| Name                            | Key Generation Scheme | Key Length (in bits) | Char to Byte conversion |
|---------------------------------|-----------------------|----------------------|-------------------------|
| PBEWithMD2AndDES                | PKCS5 Scheme 1        | 64                   | 8 bit chars             |
| PBEWithMD2AndRC2                | PKCS5 Scheme 1        | 128                  | 8 bit chars             |
| PBEWithMD5AndDES                | PKCS5 Scheme 1        | 64                   | 8 bit chars             |
| PBEWithMD5AndRC2                | PKCS5 Scheme 1        | 128                  | 8 bit chars             |
| PBEWithSHA1AndDES               | PKCS5 Scheme 1        | 64                   | 8 bit chars             |
| PBEWithSHA1AndRC2               | PKCS5 Scheme 1        | 128                  | 8 bit chars             |
| PBKDF2WithHmacSHA1              | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA1AndUTF8       | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA1And8bit       | PKCS5 Scheme 2        | variable             | 8 bit chars             |
| PBKDF2WithHmacSHA224            | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA256            | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA384            | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA512            | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA3-224          | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA3-256          | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA3-384          | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSHA3-512          | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacGOST3411          | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBKDF2WithHmacSM3               | PKCS5 Scheme 2        | variable             | UTF-8 chars             |
| PBEWithSHAAnd2-KeyTripleDES-CBC | PKCS12                | 128                  | 16 bit chars            |
| PBEWithSHAAnd3-KeyTripleDES-CBC | PKCS12                | 192                  | 16 bit chars            |
| PBEWithSHAAnd128BitRC2-CBC      | PKCS12                | 128                  | 16 bit chars            |
| PBEWithSHAAnd40BitRC2-CBC       | PKCS12                | 40                   | 16 bit chars            |
| PBEWithSHAAnd128BitRC4          | PKCS12                | 128                  | 16 bit chars            |
| PBEWithSHAAnd40BitRC4           | PKCS12                | 40                   | 16 bit chars            |
| PBEWithSHAAndTwofish-CBC        | PKCS12                | 256                  | 16 bit chars            |
| PBEWithSHAAndIDEA-CBC           | PKCS12                | 128                  | 16 bit chars            |

### 6.3 Certificates

The Bouncy Castle provider will read X.509 certficates (v2 or v3) as per the examples in the java.security.cert.CertificateFactory class. They can be provided either in the normal PEM encoded format, or as DER binaries.

The CertificateFactory will also read X.509 CRLs (v2) from either PEM or DER encodings.

In addition to the classes in the org.bouncycastle.asn1.x509 package for certificate, CRLs, and OCSP, CRMF, and CMP message generation a more JCE "friendly" class is provided in the package org.bouncycastle.cert. The JCE "friendly" classes found in the jcajce subpackages support RSA, DSA, GOST, DTSU, and EC-DSA.

### 6.4 Keystore

The Bouncy Castle package has four implementation of a keystore.

The first "BKS" is a keystore that will work with the keytool in the same fashion as the Sun "JKS" keystore. The keystore is resistent to tampering but not inspection.

The second, **Keystore.BouncyCastle**, or **Keystore.UBER** will only work with the keytool if the password is provided on the command line, as the entire keystore is encrypted with a PBE based on SHA1 and Twofish. **PBEWithSHAAndTwofish-CBC**. This makes the entire keystore resistant to tampering and inspection, and forces verification. The Sun JDK provided keytool will attempt to load a keystore even if no password is given, this is impossible for this version. (One might wonder about going to all this trouble and then having the password on the command line! New keytool anyone?).

In the first case, the keys are encrypted with 3-Key-TripleDES.

The third is a PKCS12 compatible keystore. PKCS12 provides a slightly different situation from the regular key store, the keystore password is currently the only password used for storing keys. Otherwise it supports all the functionality required for it to be used with the keytool. In some situations other libraries always expect to be dealing with Sun certificates, if this is the case use PKCS12-DEF, and the certificates produced by the key store will be made using the default provider. In the default case PKCS12 uses 3DES for key protection and 40 bit RC2 for protecting the certificates. It is also possible to use 3DES for both by using PKCS12-3DES-3DES or PKCS12-DEF-3DES-3DES as the KeyStore type.

There is an example program that produces PKCS12 files suitable for loading into browsers. It is in the package org.bouncycastle.jce.examples.

The fourth is the BCFKS key store which is a FIPS compliant key store which is also designed for general key storage and based on ASN.1. This key store type is encrypted and supports the use of SCRYPT and the storage of some symmetric key types.

### 6.5 Additional support classes for Elliptic Curve.

There are no classes for supporting EC in the JDK prior to JDK 1.5. If you are using an earlier JDK you can find classes for using EC in the following packages:

- org.bouncycastle.jce.spec
- org.bouncycastle.jce.interfaces
- org.bouncycastle.jce

### 7.0 BouncyCastle S/MIME

To be able to fully compile and utilise the BouncyCastle S/MIME package (including the test classes) you need the jar files for the following APIs.

- Junit - <https://www.junit.org>
- JavaMail - <https://java.sun.com/products/javamail/index.html>
- The Java Activation Framework - <https://java.sun.com/products/javabeans/glasgow/jaf.html>

### 7.1 Setting up BouncyCastle S/MIME in JavaMail

The BouncyCastle S/MIME handlers may be set in JavaMail two ways.

- STATICALLY  
  Add the following entries to the mailcap file:

          application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature
          application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime
          application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature
          application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime
          multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed
          

- DYNAMICALLY  
  The following code will add the BouncyCastle S/MIME handlers dynamically:

          import javax.activation.MailcapCommandMap;
          import javax.activation.CommandMap;

          public static void setDefaultMailcap()
          {
              MailcapCommandMap _mailcap =
                  (MailcapCommandMap)CommandMap.getDefaultCommandMap();

              _mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
              _mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
              _mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
              _mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
              _mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

              CommandMap.setDefaultCommandMap(_mailcap);
          } 
          
