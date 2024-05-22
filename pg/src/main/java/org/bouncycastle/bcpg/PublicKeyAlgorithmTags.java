package org.bouncycastle.bcpg;

/**
 * Public Key Algorithm IDs.
 *
 * @see <a href="RFC4880 - Public-Key Algorithms">
 *     https://www.rfc-editor.org/rfc/rfc4880.html#section-9.1</a>
 * @see <a href="LibrePGP - Public-Key Algorithms">
 *     https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-public-key-algorithms</a>
 * @see <a href="Crypto-Refresh - Public-Key Algorithms">
 *     https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-public-key-algorithms</a>
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
     * C-R compliant implementations MUST implement support for this.
     */
    int X25519 = 25;           // X25519
    /**
     * X448 encryption algorithm.
     */
    int X448 = 26;             // X448
    /**
     * Ed25519 signing algorithm.
     * C-R compliant implementations MUST implement support for this.
     */
    int Ed25519 = 27;          // new style Ed25519
    /**
     * Ed448 signing algorithm.
     */
    int Ed448 = 28;            // new style Ed448

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
