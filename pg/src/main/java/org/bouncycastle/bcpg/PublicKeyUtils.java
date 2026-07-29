package org.bouncycastle.bcpg;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;

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
     * Return true, if the passed in {@link PGPPublicKey} is based on X25519, either the legacy variant via
     * {@link PublicKeyAlgorithmTags#ECDH} or the more modern {@link PublicKeyAlgorithmTags#X25519}.
     *
     * @param key component key
     * @return true if key is X25519 key
     */
    public static boolean isX25519Key(PGPPublicKey key)
    {
        if (key.getAlgorithm() == PublicKeyAlgorithmTags.X25519)
        {
            return true;
        }
        if (key.getAlgorithm() != PublicKeyAlgorithmTags.ECDH)
        {
            return false;
        }
        ECPublicBCPGKey ecKey = (ECPublicBCPGKey) key.getPublicKeyPacket().getKey();
        return "Curve25519".equals(PGPUtil.getCurveName(ecKey.getCurveOID()));
    }
}
