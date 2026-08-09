package org.bouncycastle.bcpg;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;

/**
 * Utility methods related to OpenPGP public key algorithms.
 */
public class PublicKeyUtils
{

    /**
     * Return true, if the public key algorithm that corresponds to the given ID is capable of signing.
     *
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

    /**
     * Return true, if the passed in {@link PublicKeyPacket} is based on X25519, either the legacy variant
     * via {@link PublicKeyAlgorithmTags#ECDH} over curve25519, or the modern
     * {@link PublicKeyAlgorithmTags#X25519}.
     *
     * @param publicKeyPacket public key packet
     * @return true if the key is an X25519 key
     */
    public static boolean isX25519Key(PublicKeyPacket publicKeyPacket)
    {
        int algorithm = publicKeyPacket.getAlgorithm();
        if (algorithm == PublicKeyAlgorithmTags.X25519)
        {
            return true;
        }
        if (algorithm != PublicKeyAlgorithmTags.ECDH)
        {
            return false;
        }
        // the algorithm tag and the key packet body can disagree on malformed input, so type-check
        // rather than cast: an ECDH tag over a non-EC body is simply not an X25519 key.
        BCPGKey key = publicKeyPacket.getKey();
        if (!(key instanceof ECPublicBCPGKey))
        {
            return false;
        }
        return CryptlibObjectIdentifiers.curvey25519.equals(((ECPublicBCPGKey)key).getCurveOID());
    }
}
