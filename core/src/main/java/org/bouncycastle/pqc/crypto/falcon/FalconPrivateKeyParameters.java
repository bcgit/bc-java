package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPrivateKeyParameters
    extends FalconKeyParameters
{
    private final byte[] pk;
    private final byte[] f;
    private final byte[] g;
    private final byte[] F;

    public FalconPrivateKeyParameters(FalconParameters parameters, byte[] f, byte[] g, byte[] F, byte[] pk_encoded)
    {
        super(true, parameters);
        this.f = Arrays.clone(f);
        this.g = Arrays.clone(g);
        this.F = Arrays.clone(F);
        this.pk = Arrays.clone(pk_encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(f, g, F);
    }

    /**
     * Return the encoded public key for this private key.
     * <p>
     * When this instance still carries the encoded public key (the usual case
     * for a freshly generated key) that encoding is returned directly. When it
     * does not — e.g. the key was reconstructed from only its private encoding
     * (f &#8214; g &#8214; F), with no public key bytes retained — the public
     * key h is recomputed from the private polynomials (h = g * f<sup>-1</sup>
     * mod (q, x<sup>n</sup>+1)) (github #2297).
     */
    public byte[] getPublicKey()
    {
        return (pk == null || pk.length == 0) ? derivePublicKey() : Arrays.clone(pk);
    }

    /**
     * Return the matching {@link FalconPublicKeyParameters} for this private
     * key, mirroring {@code MLDSAPrivateKeyParameters.getPublicKeyParameters()}.
     * Lets wallet / HSM code recover the public key from a stored private key
     * without re-running keygen; see {@link #getPublicKey()} for how the key is
     * recovered when no public key bytes were retained (github #2297).
     */
    public FalconPublicKeyParameters getPublicKeyParameters()
    {
        return new FalconPublicKeyParameters(getParameters(), getPublicKey());
    }

    /**
     * Recompute the encoded public key (h = g * f^-1 mod (q, x^n+1)) from the
     * private polynomials, for the case where no encoded public key was
     * retained. The returned bytes match {@link #getPublicKey()} of a freshly
     * generated key.
     *
     * @throws IllegalStateException if the private polynomials cannot be decoded
     *                               or f is not invertible mod q.
     */
    private byte[] derivePublicKey()
    {
        int logn = getParameters().getLogN();
        int n = 1 << logn;
        int bits = FalconCodec.max_fg_bits[logn];

        byte[] fc = new byte[n];
        byte[] gc = new byte[n];

        if (FalconCodec.trim_i8_decode(fc, logn, bits, f, 0, f.length) == 0)
        {
            throw new IllegalStateException("unable to decode f");
        }
        if (FalconCodec.trim_i8_decode(gc, logn, bits, g, 0, g.length) == 0)
        {
            throw new IllegalStateException("unable to decode g");
        }

        short[] h = new short[n];
        short[] tmp = new short[n];
        if (FalconVrfy.compute_public(h, 0, fc, gc, logn, tmp, 0) == 0)
        {
            throw new IllegalStateException("unable to recover public key: f not invertible mod q");
        }

        byte[] enc = new byte[1 + (14 * n / 8)];
        if (FalconCodec.modq_encode(enc, enc.length - 1, h, logn) != enc.length - 1)
        {
            throw new IllegalStateException("public key encoding failed");
        }

        return Arrays.copyOfRange(enc, 1, enc.length);
    }

    public byte[] getSpolyf()
    {
        return Arrays.clone(f);
    }

    public byte[] getG()
    {
        return Arrays.clone(g);
    }

    public byte[] getSpolyF()
    {
        return Arrays.clone(F);
    }
}
