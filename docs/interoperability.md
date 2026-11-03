# Bouncy Castle Java Specification & Interoperability

The following provides an overview of the formats, protocols and algorithms supported by the Bouncy Castle Java APIs, with links to the external standards that define them. It is the source for the Specification & Interoperability page on bouncycastle.org, and is updated with each release. For the class and algorithm names used to reach each of these, see [specifications.md](specifications.md).

This page covers the Bouncy Castle Java APIs (the bc*-jdk18on and related jars). The FIPS, LTS and C# releases have their own documentation.

## Packages and Standards

Bouncy Castle Java supports the following formats and standards.

| Supported Standard | External Reference |
|---|---|
| X.509 and PKIX certificates and CRLs | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), [RFC 9925](https://www.rfc-editor.org/rfc/rfc9925) (unsigned certificates) |
| CMP: Certificate Management Protocol | [RFC 9810](https://www.rfc-editor.org/rfc/rfc9810), [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) |
| CMS/PKCS#7: Cryptographic Message Syntax | [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652), [RFC 9629](https://www.rfc-editor.org/rfc/rfc9629) (KEMs), [RFC 9690](https://www.rfc-editor.org/rfc/rfc9690) (RSA-KEM), [RFC 9709](https://www.rfc-editor.org/rfc/rfc9709) (HKDF key derivation), [RFC 9936](https://www.rfc-editor.org/rfc/rfc9936) (ML-KEM), [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882) (ML-DSA), [RFC 9814](https://www.rfc-editor.org/rfc/rfc9814) (SLH-DSA), [RFC 5753](https://www.rfc-editor.org/rfc/rfc5753) (ECC) |
| CRMF: Certificate Request Message Format | [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) |
| DANE: DNS-Based Authentication of Named Entities, including SMIMEA records | [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698), [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671), [RFC 8162](https://www.rfc-editor.org/rfc/rfc8162) |
| DVCS: Data Validation and Certification Server Protocols | [RFC 3029](https://www.rfc-editor.org/rfc/rfc3029) |
| DTLS: Datagram Transport Layer Security 1.2 and 1.3 | [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347), [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) |
| EAC: Extended Access Control (EAC) Certificates | [BSI TR-03110](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03110/BSI_TR-03110_Part-3-V2_2.pdf?__blob=publicationFile&v=1) |
| ERS: Evidence Record Syntax | [RFC 4998](https://www.rfc-editor.org/rfc/rfc4998) |
| EST: Enrollment over Secure Transport | [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) |
| HPKE: Hybrid Public Key Encryption | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| ITS: Intelligent Transportation Systems | [ETSI ITS](https://www.etsi.org/technologies/automotive-intelligent-transport) |
| MLS: Messaging Layer Security | [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) |
| OpenPGP | [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), [RFC 9980](https://www.rfc-editor.org/rfc/rfc9980) (post-quantum), [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC 6637](https://www.rfc-editor.org/rfc/rfc6637) |
| PKCS#10: Certification Request Syntax | [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) |
| PKCS#12: Personal Information Exchange Syntax | [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292), [RFC 9879](https://www.rfc-editor.org/rfc/rfc9879) (PBMAC1) |
| TLS: Transport Layer Security 1.2 and 1.3 | [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), [RFC 5932](https://www.rfc-editor.org/rfc/rfc5932), [RFC 6209](https://www.rfc-editor.org/rfc/rfc6209), [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) |
| TSP: Time-Stamp Protocol | [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161), [RFC 5544](https://www.rfc-editor.org/rfc/rfc5544) |
| Algorithm Identifiers for EdDSA and XDH | [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) |
| Algorithm Identifiers for HSS/LMS and XMSS | [RFC 9802](https://www.rfc-editor.org/rfc/rfc9802) |
| Algorithm Identifiers for ML-DSA | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881) |
| Algorithm Identifiers for ML-KEM | [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) |
| Algorithm Identifiers for SLH-DSA | [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909) |

## Algorithms & Key Types

Bouncy Castle supports the following public key algorithm types and key sizes/curves.

| Algorithm | External Reference |
|---|---|
| Diffie-Hellman | [SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) |
| DSA | FIPS PUB 186-4, [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) |
| DSTU 4145 | DSTU 4145-2002 |
| ECDSA/ECDH | X9.62, FIPS PUB 186-4, [RFC 5639](https://www.rfc-editor.org/rfc/rfc5639), [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979), [SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) |
| EdDSA/XDH | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) |
| ElGamal | [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) |
| GOST | [RFC 4490](https://www.rfc-editor.org/rfc/rfc4490), [RFC 7836](https://www.rfc-editor.org/rfc/rfc7836) |
| RSA | [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017), FIPS PUB 186-4, SP 800-56B, [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474) (blind signatures) |
| SM2 | [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) |

The post-quantum public key algorithms are listed [below](#post-quantum-algorithm-support).

### Symmetric Key Algorithms

Bouncy Castle supports the following symmetric key algorithms.

| Algorithm | External Reference |
|---|---|
| AES | FIPS PUB 197, [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649) |
| ARIA | [RFC 5794](https://www.rfc-editor.org/rfc/rfc5794) |
| Ascon (AEAD) | [SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) |
| Camellia | [RFC 3713](https://www.rfc-editor.org/rfc/rfc3713), [RFC 3657](https://www.rfc-editor.org/rfc/rfc3657) |
| CAST5 | [RFC 2144](https://www.rfc-editor.org/rfc/rfc2144) |
| CAST6 | [RFC 2612](https://www.rfc-editor.org/rfc/rfc2612) |
| ChaCha20, ChaCha20-Poly1305 | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| DSTU 7624 | DSTU 7624:2014 |
| GOST 28147 | [RFC 5830](https://www.rfc-editor.org/rfc/rfc5830) |
| GOST 3412-2015 | [RFC 7801](https://www.rfc-editor.org/rfc/rfc7801) |
| Grain | eSTREAM Project |
| HC | eSTREAM Project |
| LEA | ISO/IEC 29192-2:2019 |
| RC2 | [RFC 2268](https://www.rfc-editor.org/rfc/rfc2268), [RFC 3217](https://www.rfc-editor.org/rfc/rfc3217) |
| RC5 | [RFC 2040](https://www.rfc-editor.org/rfc/rfc2040) |
| Salsa20 | eSTREAM Project |
| SEED | [RFC 4269](https://www.rfc-editor.org/rfc/rfc4269) |
| SM4 | [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) |
| TripleDES | FIPS PUB 46-3, [RFC 3217](https://www.rfc-editor.org/rfc/rfc3217) |

## Message Digests and Expandable Output Functions

Bouncy Castle supports the following Message Digests and Expandable Output Functions (XOFs).

| Algorithm | External Reference |
|---|---|
| Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 | [SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) |
| BLAKE2 | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693) |
| BLAKE3 | [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs) |
| cSHAKE-128, cSHAKE-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| KangarooTwelve | [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861) |
| KMAC-128, KMAC-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| MD5 | [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321) |
| ParallelHash-128, ParallelHash-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320 | ISO/IEC 10118-3 |
| SHA-1 | FIPS PUB 180-4 |
| SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS PUB 180-4 |
| SHA3-224, SHA3-256, SHA3-384, SHA3-512 | FIPS PUB 202 |
| SHAKE-128, SHAKE-256 | FIPS PUB 202, [RFC 8702](https://www.rfc-editor.org/rfc/rfc8702) |
| SM3 | [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) |
| Tiger | Project NESSIE |
| TupleHash-128, TupleHash-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| Whirlpool | Project NESSIE, ISO/IEC 10118-3 |

## Post-Quantum Algorithm Support

The following post-quantum algorithms are standardized and implemented.

### Key Encapsulation Mechanisms (KEMs)

| Key Encapsulation Mechanism | External Reference |
|---|---|
| ML-KEM | [FIPS PUB 203](https://csrc.nist.gov/pubs/fips/203/final) |

### Signature Algorithms

| Signature Algorithm | External Reference |
|---|---|
| ML-DSA | [FIPS PUB 204](https://csrc.nist.gov/pubs/fips/204/final) |
| SLH-DSA | [FIPS PUB 205](https://csrc.nist.gov/pubs/fips/205/final) |
| LMS/HSS | [SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final), [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554), [RFC 8708](https://www.rfc-editor.org/rfc/rfc8708) |
| XMSS, XMSS^MT | [SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final), [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391) |

### Hybrid and Composite Algorithms

| Algorithm | External Reference |
|---|---|
| Composite ML-DSA signatures | [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) |
| Composite ML-KEM | [draft-ietf-lamps-pq-composite-kem](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/) |
| X-Wing | [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) |

## Other Post-Quantum Algorithms

For further details on these algorithms, refer to [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography).

The post-quantum algorithms below have been submitted to the NIST and other PQC standardization processes, but are not yet standardized. They are available for experimenting and hybrid cryptography, but are unsuitable for long-term use until standardized.

### Key Encapsulation Mechanisms (KEMs)

| Key Encapsulation Mechanism | Status |
|---|---|
| HQC | Selected by NIST for standardization ([NIST IR 8545](https://csrc.nist.gov/pubs/ir/8545/final)) |
| Classic McEliece | NIST Round 4 candidate, being standardized in ISO/IEC 18033-2, recommended by BSI |
| FrodoKEM | NIST Round 3 alternate candidate, being standardized in ISO/IEC 18033-2, recommended by BSI |
| BIKE | NIST Round 4 candidate, not selected |
| NTRU | NIST Round 3 finalist, not selected |
| NTRU Prime (Streamlined NTRU Prime, NTRU LPRime) | NIST Round 3 alternate candidate, not selected |
| SABER | NIST Round 3 finalist, not selected |
| NTRU+, SMAUG-T | KpqC (Korean Post-Quantum Cryptography) competition |

### Signature Algorithms

| Signature Algorithm | Status |
|---|---|
| Falcon | Selected by NIST for standardization as FN-DSA (FIPS 206, in development) |
| MAYO, SNOVA, QR-UOV, UOV, FAEST, MQOM, SDitH, SQIsign | NIST additional digital signature candidates |
| AIMer, HAETAE | KpqC (Korean Post-Quantum Cryptography) competition |

## CRL, OCSP and Certificate Distribution

Bouncy Castle supports the following CRL formats and standards.

| Supported Standard | External Reference |
|---|---|
| CRL creation and URL based CRL Distribution Points | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) |
| Online Certificate Status Protocol (OCSP), including the AIA extension and the TLS Feature (must-staple) extension | [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960), [RFC 2560](https://www.rfc-editor.org/rfc/rfc2560), [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019), [RFC 8954](https://www.rfc-editor.org/rfc/rfc8954), [RFC 7633](https://www.rfc-editor.org/rfc/rfc7633) |

## Certificate Enrollment Protocols

The following lists Certificate Enrollment Protocols and/or interfaces.

| Protocol/Interface | External Reference |
|---|---|
| Certificate Management Protocol (CMP) | [RFC 9810](https://www.rfc-editor.org/rfc/rfc9810), [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) |
| Certificate Management over CMS (CMC) Full PKI Response, as used by EST | [RFC 5272](https://www.rfc-editor.org/rfc/rfc5272) |
| Enrollment over Secure Transport (EST) | [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) |
