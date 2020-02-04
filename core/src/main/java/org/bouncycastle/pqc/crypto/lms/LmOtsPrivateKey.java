package org.bouncycastle.pqc.crypto.lms;

public class LmOtsPrivateKey
{
    private final LmOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] masterSecret;

    public LmOtsPrivateKey(LmOtsParameters parameter, byte[] i, int q, byte[] masterSecret)
    {
        this.parameter = parameter;
        I = i;
        this.q = q;
        this.masterSecret = masterSecret;
    }

    SeedDerive getDerivationFunction()
    {
        SeedDerive derive = new SeedDerive(I, masterSecret, DigestUtil.getDigest(parameter.getDigestOID()));
        derive.setQ(q);
        return derive;
    }

    public LmOtsParameters getParameter()
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
