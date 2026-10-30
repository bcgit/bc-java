package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Lightweight representation of a composite OpenPGP key of RFC 9980: the two independent component keys of
 * an ML-DSA + EdDSA signing key ({@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags#MLDSA65_Ed25519},
 * {@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags#MLDSA87_Ed448}) or of an ML-KEM + ECDH encryption key
 * ({@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags#MLKEM768_X25519},
 * {@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags#MLKEM1024_X448}).
 * <p>
 * {@link BcPGPKeyConverter} returns an instance of this class for such keys and expects one when asked to
 * build the OpenPGP key packets, and {@link BcPGPKeyPair} takes an {@link org.bouncycastle.crypto.AsymmetricCipherKeyPair}
 * whose halves are instances of it. The traditional component is an
 * {@link org.bouncycastle.crypto.params.Ed25519PublicKeyParameters} / {@link org.bouncycastle.crypto.params.Ed448PublicKeyParameters}
 * or {@link org.bouncycastle.crypto.params.X25519PublicKeyParameters} / {@link org.bouncycastle.crypto.params.X448PublicKeyParameters}
 * (or the private key counterpart); the post-quantum component is an
 * {@link org.bouncycastle.crypto.params.MLDSAPublicKeyParameters} or {@link org.bouncycastle.crypto.params.MLKEMPublicKeyParameters}
 * (or the private key counterpart).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-1.4.1">
 *     RFC 9980 - Standalone and Composite Multi-Algorithm Schemes</a>
 */
public class BcPGPCompositeKeyParameters
    extends AsymmetricKeyParameter
{
    private final AsymmetricKeyParameter traditionalKey;
    private final AsymmetricKeyParameter postQuantumKey;

    /**
     * Combine the two component keys of a composite key.
     *
     * @param isPrivate true if both components are private keys, false if both are public keys
     * @param traditionalKey the EdDSA or ECDH component
     * @param postQuantumKey the ML-DSA or ML-KEM component
     */
    public BcPGPCompositeKeyParameters(boolean isPrivate, AsymmetricKeyParameter traditionalKey, AsymmetricKeyParameter postQuantumKey)
    {
        super(isPrivate);

        if (traditionalKey == null || postQuantumKey == null)
        {
            throw new NullPointerException("both component keys must be supplied");
        }
        if (traditionalKey.isPrivate() != isPrivate || postQuantumKey.isPrivate() != isPrivate)
        {
            throw new IllegalArgumentException("component keys must both be " + (isPrivate ? "private" : "public") + " keys");
        }

        this.traditionalKey = traditionalKey;
        this.postQuantumKey = postQuantumKey;
    }

    /**
     * Return the traditional (EdDSA or ECDH) component key.
     *
     * @return traditional component
     */
    public AsymmetricKeyParameter getTraditionalKey()
    {
        return traditionalKey;
    }

    /**
     * Return the post-quantum (ML-DSA or ML-KEM) component key.
     *
     * @return post-quantum component
     */
    public AsymmetricKeyParameter getPostQuantumKey()
    {
        return postQuantumKey;
    }
}
