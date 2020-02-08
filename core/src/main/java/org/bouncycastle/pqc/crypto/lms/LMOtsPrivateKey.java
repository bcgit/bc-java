package org.bouncycastle.pqc.crypto.lms;

class LMOtsPrivateKey
{
    private final LMOtsParameters parameter;
    private final byte[] I;
    private final int q;
    private final byte[] masterSecret;

    public LMOtsPrivateKey(LMOtsParameters parameter, byte[] i, int q, byte[] masterSecret)
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


    public LMOtsParameters getParameter()
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
