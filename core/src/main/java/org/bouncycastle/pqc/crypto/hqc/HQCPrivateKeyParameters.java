package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;

/**
 * An HQC decapsulation key. Its encoding is dkKEM = seedKEM, the 32-byte seed from which the HQC
 * specification of 2026-10-12 derives the whole key pair (Section 3.7, Table 9); the expanded form
 * decapsulation works on - ekPKE, seedPKE.dk and sigma - is derived from it on first use and kept,
 * the caching the specification allows to offset the cost of re-deriving it on every decapsulation.
 */
public class HQCPrivateKeyParameters
    extends HQCKeyParameters
{
    private final byte[] seed;

    private byte[] expanded;

    /**
     * @param params the parameter set.
     * @param sk     the 32-byte seedKEM.
     */
    public HQCPrivateKeyParameters(HQCParameters params, byte[] sk)
    {
        super(true, params);

        if (sk.length != params.getSecretKeyBytes())
        {
            throw new IllegalArgumentException("'sk' has invalid length");
        }

        this.seed = Arrays.clone(sk);
    }

    HQCPrivateKeyParameters(HQCParameters params, byte[] seed, byte[] expanded)
    {
        this(params, seed);

        this.expanded = Arrays.clone(expanded);
    }

    /**
     * Return the encapsulation key this decapsulation key pairs with, derived from the seed.
     *
     * @return the matching public key parameters.
     */
    public HQCPublicKeyParameters getPublicKeyParameters()
    {
        byte[] expanded = getExpandedKey();

        return new HQCPublicKeyParameters(getParameters(),
            Arrays.copyOfRange(expanded, 0, getParameters().getPublicKeyBytes()));
    }

    /**
     * @return a copy of the 32-byte seedKEM.
     */
    public byte[] getPrivateKey()
    {
        return Arrays.clone(this.seed);
    }

    /**
     * @return the key's encoding, the 32-byte seedKEM.
     */
    public byte[] getEncoded()
    {
        return Arrays.clone(this.seed);
    }

    /**
     * The expanded key ekPKE || seedPKE.dk || sigma, derived on first call and cached. Callers
     * read it in place and must not modify it.
     */
    synchronized byte[] getExpandedKey()
    {
        if (expanded == null)
        {
            expanded = getParameters().getEngine().expandSecretKey(seed);
        }

        return expanded;
    }
}
