package org.bouncycastle.bcpg;

/**
 * Utility methods related to OpenPGP public key algorithms.
 */
public class PublicKeyUtils
{

    /**
     * Return true, if the public key algorithm that corresponds to the given ID is capable of signing.
     * @param publicKeyAlgorithm public key algorithm id
     * @return true if algorithm can sign
     */
    public static boolean isSigningAlgorithm(int publicKeyAlgorithm)
    {
        switch (publicKeyAlgorithm)
        {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            case PublicKeyAlgorithmTags.DSA:
            case PublicKeyAlgorithmTags.ECDSA:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            case PublicKeyAlgorithmTags.Ed25519:
            case PublicKeyAlgorithmTags.Ed448:
                return true;
            default:
                return false;
        }
    }

    /**
     * Return true, if the public key algorithm that corresponds to the given ID is capable of encryption.
     * @param publicKeyAlgorithm public key algorithm id
     * @return true if algorithm can encrypt
     */
    public static boolean isEncryptionAlgorithm(int publicKeyAlgorithm)
    {
        switch (publicKeyAlgorithm)
        {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ECDH:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
            case PublicKeyAlgorithmTags.X25519:
            case PublicKeyAlgorithmTags.X448:
                return true;
            default:
                return false;
        }
    }
}
