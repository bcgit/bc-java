package org.bouncycastle.bcpg;

/**
 * Public Key Algorithm IDs.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
 *     RFC9580 - Public-Key Algorithms</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880.html#section-9.1">
 *     RFC4880 - Public-Key Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-public-key-algorithms">
 *     LibrePGP - Public-Key Algorithms</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-11">
 *     RFC 9980 - Post-Quantum Cryptography in OpenPGP, IANA Considerations</a>
 */
public interface PublicKeyAlgorithmTags 
{
    /**
     * RSA encryption/signing algorithm.
     */
    int RSA_GENERAL = 1;       // RSA (Encrypt or Sign)
    /**
     * Deprecated tag for encrypt-only RSA.
     * MUST NOT be generated.
     * @deprecated use {@link #RSA_GENERAL} instead.
     */
    int RSA_ENCRYPT = 2;       // RSA Encrypt-Only
    /**
     * Deprecated tag for sign-only RSA.
     * MUST NOT be generated.
     * @deprecated use {@link #RSA_GENERAL} instead.
     */
    int RSA_SIGN = 3;          // RSA Sign-Only
    /**
     * Encrypt-only ElGamal.
     */
    int ELGAMAL_ENCRYPT = 16;  // Elgamal (Encrypt-Only), see [ELGAMAL]
    /**
     * DSA.
     */
    int DSA = 17;              // DSA (Digital Signature Standard)
    /**
     * Deprecated tag for ECDH.
     * @deprecated use {@link #ECDH} instead.
     */
    int EC = 18;               // Misnamed constant
    /**
     * Elliptic curve Diffie-Hellman.
     */
    int ECDH = 18;             // Elliptic Curve Diffie-Hellman
    /**
     * Elliptic curve digital signing algorithm.
     */
    int ECDSA = 19;            // Elliptic Curve Digital Signing Algorithm
    /**
     * Reserved tag for sign+encrypt ElGamal.
     * MUST NOT be generated.
     * An implementation MUST NOT generate ElGamal signatures.
     * @deprecated use {@link #ELGAMAL_ENCRYPT} instead.
     */
    int ELGAMAL_GENERAL = 20;  // Reserved Elgamal (Encrypt or Sign)
    /**
     * Reserved tag for IETF-style S/MIME Diffie-Hellman.
     */
    int DIFFIE_HELLMAN = 21;   // Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    /**
     * Misnamed tag for legacy EdDSA.
     * @deprecated use {@link #EDDSA_LEGACY} instead.
     */
    int EDDSA = 22;            // EdDSA - (internet draft, but appearing in use); misnamed constant
    /**
     * Legacy EdDSA (curve identified by OID).
     * MUST NOT be used with v6 keys (use {@link #Ed25519}, {@link #Ed448} instead).
     */
    int EDDSA_LEGACY = 22;     // new name for old EDDSA tag.
    /**
     * Reserved tag for AEDH.
     */
    int AEDH = 23;             // Reserved
    /**
     * Reserved tag for AEDSA.
     */
    int AEDSA = 24;            // Reserved
    /**
     * X25519 encryption algorithm.
     * RFC9580-compliant implementations MUST implement support for this.
     */
    int X25519 = 25;           // X25519
    /**
     * X448 encryption algorithm.
     */
    int X448 = 26;             // X448
    /**
     * Ed25519 signing algorithm.
     * RFC9580-compliant implementations MUST implement support for this.
     */
    int Ed25519 = 27;          // new style Ed25519
    /**
     * Ed448 signing algorithm.
     */
    int Ed448 = 28;            // new style Ed448

    /**
     * ML-DSA-65 + Ed25519 composite signature algorithm (RFC 9980 sec. 5).
     * Conformant implementations MUST implement this algorithm. MUST only be used with v6 keys and signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5">
     *     RFC 9980 - Composite Signature Schemes</a>
     */
    int MLDSA65_Ed25519 = 30;

    /**
     * ML-DSA-87 + Ed448 composite signature algorithm (RFC 9980 sec. 5).
     * MUST only be used with v6 keys and signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5">
     *     RFC 9980 - Composite Signature Schemes</a>
     */
    int MLDSA87_Ed448 = 31;

    /**
     * SLH-DSA-SHAKE-128s signature algorithm (RFC 9980 sec. 6).
     * MUST only be used with v6 keys and signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6">
     *     RFC 9980 - SLH-DSA</a>
     */
    int SLHDSA_SHAKE_128s = 32;

    /**
     * SLH-DSA-SHAKE-128f signature algorithm (RFC 9980 sec. 6).
     * MUST only be used with v6 keys and signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6">
     *     RFC 9980 - SLH-DSA</a>
     */
    int SLHDSA_SHAKE_128f = 33;

    /**
     * SLH-DSA-SHAKE-256s signature algorithm (RFC 9980 sec. 6).
     * MUST only be used with v6 keys and signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6">
     *     RFC 9980 - SLH-DSA</a>
     */
    int SLHDSA_SHAKE_256s = 34;

    /**
     * ML-KEM-768 + X25519 composite encryption algorithm (RFC 9980 sec. 4).
     * Conformant implementations MUST implement this algorithm. It is the only PQ(/T) algorithm that may also be
     * used in a v4 (encryption-capable sub)key; all others MUST only be used with v6 keys.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4">
     *     RFC 9980 - Composite KEM Schemes</a>
     */
    int MLKEM768_X25519 = 35;

    /**
     * ML-KEM-1024 + X448 composite encryption algorithm (RFC 9980 sec. 4).
     * MUST only be used with v6 keys.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4">
     *     RFC 9980 - Composite KEM Schemes</a>
     */
    int MLKEM1024_X448 = 36;

    int EXPERIMENTAL_1 = 100;
    int EXPERIMENTAL_2 = 101;
    int EXPERIMENTAL_3 = 102;
    int EXPERIMENTAL_4 = 103;
    int EXPERIMENTAL_5 = 104;
    int EXPERIMENTAL_6 = 105;
    int EXPERIMENTAL_7 = 106;
    int EXPERIMENTAL_8 = 107;
    int EXPERIMENTAL_9 = 108;
    int EXPERIMENTAL_10 = 109;
    int EXPERIMENTAL_11 = 110;
}
