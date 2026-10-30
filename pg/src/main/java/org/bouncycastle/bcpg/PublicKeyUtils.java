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
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
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
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return true;
        default:
            return false;
        }
    }

    /**
     * Return true, if the public key algorithm is one of the post-quantum (PQ) or post-quantum/traditional (PQ/T)
     * algorithms of RFC 9980: the ML-DSA + EdDSA and ML-KEM + ECDH composites and the SLH-DSA code points.
     *
     * @param publicKeyAlgorithm public key algorithm id
     * @return true if the algorithm is specified by RFC 9980
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-2.1">
     *     RFC 9980 - Algorithm Specifications</a>
     */
    public static boolean isPQCAlgorithm(int publicKeyAlgorithm)
    {
        return isMLDSACompositeAlgorithm(publicKeyAlgorithm)
            || isSLHDSAAlgorithm(publicKeyAlgorithm)
            || isMLKEMCompositeAlgorithm(publicKeyAlgorithm);
    }

    /**
     * Return true, if the public key algorithm is one of the ML-DSA + EdDSA composite signature algorithms
     * of RFC 9980 sec. 5.
     *
     * @param publicKeyAlgorithm public key algorithm id
     * @return true for {@link PublicKeyAlgorithmTags#MLDSA65_Ed25519} and {@link PublicKeyAlgorithmTags#MLDSA87_Ed448}
     */
    public static boolean isMLDSACompositeAlgorithm(int publicKeyAlgorithm)
    {
        return publicKeyAlgorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519
            || publicKeyAlgorithm == PublicKeyAlgorithmTags.MLDSA87_Ed448;
    }

    /**
     * Return true, if the public key algorithm is one of the SLH-DSA signature algorithms of RFC 9980 sec. 6.
     *
     * @param publicKeyAlgorithm public key algorithm id
     * @return true for {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128s}, {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128f}
     * and {@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_256s}
     */
    public static boolean isSLHDSAAlgorithm(int publicKeyAlgorithm)
    {
        return publicKeyAlgorithm == PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s
            || publicKeyAlgorithm == PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f
            || publicKeyAlgorithm == PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s;
    }

    /**
     * Return true, if the public key algorithm is one of the ML-KEM + ECDH composite encryption algorithms
     * of RFC 9980 sec. 4.
     *
     * @param publicKeyAlgorithm public key algorithm id
     * @return true for {@link PublicKeyAlgorithmTags#MLKEM768_X25519} and {@link PublicKeyAlgorithmTags#MLKEM1024_X448}
     */
    public static boolean isMLKEMCompositeAlgorithm(int publicKeyAlgorithm)
    {
        return publicKeyAlgorithm == PublicKeyAlgorithmTags.MLKEM768_X25519
            || publicKeyAlgorithm == PublicKeyAlgorithmTags.MLKEM1024_X448;
    }

    /**
     * Return true, if RFC 9980 permits the public key algorithm in a key packet of the given version.
     * All PQ(/T) algorithms are to be used only in v6 keys, with the single exception of
     * {@link PublicKeyAlgorithmTags#MLKEM768_X25519}, which is also allowed in v4 encryption-capable
     * subkeys (RFC 9980 sec. 3.5 and 4.3.2). The method has no opinion on algorithms outside RFC 9980 and
     * returns true for them.
     *
     * @param publicKeyAlgorithm public key algorithm id
     * @param keyVersion key packet version
     * @return false if RFC 9980 forbids the algorithm in a key of that version, true otherwise
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-3.5">
     *     RFC 9980 - Key Version Binding</a>
     */
    public static boolean isAlgorithmAllowedForKeyVersion(int publicKeyAlgorithm, int keyVersion)
    {
        if (!isPQCAlgorithm(publicKeyAlgorithm))
        {
            return true;
        }
        if (keyVersion == PublicKeyPacket.VERSION_6)
        {
            return true;
        }
        return publicKeyAlgorithm == PublicKeyAlgorithmTags.MLKEM768_X25519 && keyVersion == PublicKeyPacket.VERSION_4;
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
