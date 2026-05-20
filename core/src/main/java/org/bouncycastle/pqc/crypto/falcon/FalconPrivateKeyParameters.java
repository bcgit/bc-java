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

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }

    /**
     * Return the matching {@link FalconPublicKeyParameters} for this private
     * key — equivalent to {@code new FalconPublicKeyParameters(getParameters(),
     * getPublicKey())}. Mirrors {@code MLDSAPrivateKeyParameters.getPublicKeyParameters()}
     * and lets wallet / HSM code recover the public key from a stored
     * private key without re-running keygen (github #2297).
     */
    public FalconPublicKeyParameters getPublicKeyParameters()
    {
        return new FalconPublicKeyParameters(getParameters(), pk);
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
