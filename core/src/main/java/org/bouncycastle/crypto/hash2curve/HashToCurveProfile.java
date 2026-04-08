package org.bouncycastle.crypto.hash2curve;

import java.math.BigInteger;

/**
 * Supported profiles for instantiating an instance of HashToEllipticCurve. Each profile supports
 * both hash_to_curve and encode_to_curve operations, according to RFC 9380
 * <p>
 * _NU_ is identical to _RO_, except that the encoding type is encode_to_curve. encode_to_curve is
 * not yet implemented in this lib, thus these options are not yet included
 */
public enum HashToCurveProfile
{

    P256_XMD_SHA_256(BigInteger.valueOf(-10), 48, 128, 1, null, null),
    P384_XMD_SHA_384(BigInteger.valueOf(-12), 72, 192, 1, null, null),
    P521_XMD_SHA_512(BigInteger.valueOf(-4), 98, 256, 1, null, null),
    CURVE25519W_XMD_SHA_512_ELL2(BigInteger.valueOf(2), 48, 128, 8, 486662, 1);
    // For future considerations
    // curve448_XOF_SHAKE256_ELL2_RO_(BigInteger.valueOf(-1), 84, 224, 4, 156326, 1),
    // edwards25519_XMD_SHA_512_ELL2_RO_(BigInteger.valueOf(2), 48, 224, 8, 486662, 1),
    // edwards448_XOF_SHAKE256_ELL2_RO_(BigInteger.valueOf(-1), 84, 224, 4, 156326, 1),

    /**
     * The z value is a value of the curve field that satisfies the following criteria:
     * <ol>
     * <li>Z is non-square in F. This is a field object e.g., F = GF(2^521 - 1).</li>
     * <li>Z is not equal to negative one -1 in the field F.</li>
     * <li>The polynomial g(x) - Z is irreducible over the field F. In this context, an irreducible
     * polynomial cannot be factored into polynomials of lower degree, also in the field F</li>
     * <li>The polynomial g(B / (Z * A)) should be a square number in the field F</li>
     * </ol>
     */
    private final BigInteger Z;
    /** Block length */
    private final int L;
    /** The target security level in bits for the curve */
    private final int k;
    /** Effective cofactor */
    private final int h;
    /** Montgomery A parameter */
    private final Integer mJ;
    /** Montgomery B parameter */
    private final Integer mK;

    HashToCurveProfile(final BigInteger z, final int l, final int k, int h, Integer mJ, Integer mK)
    {
        this.Z = z;
        this.L = l;
        this.k = k;
        this.h = h;
        this.mJ = mJ;
        this.mK = mK;
    }

    /**
     * Retrieves the security level in bits associated with this instance.
     *
     * @return the value of the field 'k' representing security level in bits
     */
    public int getK()
    {
        return k;
    }

    /**
     * Retrieves the value of the field 'L' representing the internal block size in bytes associated
     * with this instance.
     *
     * @return the value of the field 'L' representing the internal block size
     */
    public int getL()
    {
        return L;
    }

    /**
     * Retrieves the value of the field 'Z'.
     *
     * @return the value of the field 'Z' as a BigInteger
     */
    public BigInteger getZ()
    {
        return Z;
    }

    /**
     * Retrieves the value of the field 'h', representing the cofactor associated with this instance.
     *
     * @return the value of the field 'h' as an integer
     */
    public int getH()
    {
        return h;
    }

    /**
     * Retrieves the value of the field 'mJ' representing the associated Montgomery equation parameter A
     *
     * @return the value of the field 'mJ' as an Integer
     */
    public Integer getmJ()
    {
        return mJ;
    }

    /**
     * Retrieves the value of the field 'mK' representing the associated Montgomery equation parameter B
     * specific to the hash-to-curve profile.
     *
     * @return the value of the field 'mK' as an Integer
     */
    public Integer getmK()
    {
        return mK;
    }
}
