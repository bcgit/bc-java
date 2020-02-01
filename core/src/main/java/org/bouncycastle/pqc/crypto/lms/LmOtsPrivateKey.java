package org.bouncycastle.pqc.crypto.lms;

public class LmOtsPrivateKey
{
    private final LmOtsParameter parameter;
    private final byte[] I;
    private final int q;
    private final byte[] masterSecret;

    public LmOtsPrivateKey(LmOtsParameter parameter, byte[] i, int q, byte[] masterSecret)
    {
        this.parameter = parameter;
        I = i;
        this.q = q;
        this.masterSecret = masterSecret;
    }

    SeedDerive getDerivationFunction()
    {
        SeedDerive derive = new SeedDerive(I, masterSecret, parameter.getH());
        derive.setQ(q);
        return derive;
    }

    public LmOtsParameter getParameter()
    {
        return parameter;
    }

    public byte[] getI()
    {
        return I;
    }

    public int getQ()
    {
        return q;
    }

    public byte[] getMasterSecret()
    {
        return masterSecret;
    }
}
