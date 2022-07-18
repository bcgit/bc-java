package org.bouncycastle.bcpg;

/**
 * Public Key Algorithm tag numbers
 */
public interface PublicKeyAlgorithmTags 
{
    int RSA_GENERAL = 1;       // RSA (Encrypt or Sign)
    int RSA_ENCRYPT = 2;       // RSA Encrypt-Only
    int RSA_SIGN = 3;          // RSA Sign-Only
    int ELGAMAL_ENCRYPT = 16;  // Elgamal (Encrypt-Only), see [ELGAMAL]
    int DSA = 17;              // DSA (Digital Signature Standard)
    /**
     * @deprecated use ECDH
     */
    int EC = 18;               // Reserved for Elliptic Curve
    int ECDH = 18;             // Reserved for Elliptic Curve (actual algorithm name)
    int ECDSA = 19;            // Reserved for ECDSA
    int ELGAMAL_GENERAL = 20;  // Elgamal (Encrypt or Sign)
    int DIFFIE_HELLMAN = 21;   // Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    int EDDSA = 22;            // EdDSA - (internet draft, but appearing in use)

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
