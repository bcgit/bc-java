package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.util.Arrays;

public class BIKEPrivateKeyParameters
    extends BIKEKeyParameters
{
    // h0
    private byte[] h0;

    // h1
    private byte[] h1;

    // sigma
    private byte[] sigma;

    /**
     * Constructor.
     *
     * @param h0    h0
     * @param h1    h1
     * @param sigma random bytes sigma
     */
    public BIKEPrivateKeyParameters(BIKEParameters bikeParameters, byte[] h0, byte[] h1, byte[] sigma)
    {
        super(true, bikeParameters);
        this.h0 = Arrays.clone(h0);
        this.h1 = Arrays.clone(h1);
        this.sigma = Arrays.clone(sigma);
    }

    byte[] getH0()
    {
        return h0;
    }

    byte[] getH1()
    {
        return h1;
    }

    byte[] getSigma()
    {
        return sigma;
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(h0, h1, sigma);
    }
}
