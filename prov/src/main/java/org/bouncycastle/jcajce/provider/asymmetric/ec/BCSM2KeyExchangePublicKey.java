package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.PublicKey;

import org.bouncycastle.util.Arrays;

public class BCSM2KeyExchangePublicKey
    implements PublicKey
{
    private  PublicKey staticPublicKey;
    private  PublicKey ephemeralPublicKey;
    private final byte[] id;

    public BCSM2KeyExchangePublicKey(PublicKey staticPublicKey, PublicKey ephemeralPublicKey, byte[] id)
    {
        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.id = Arrays.clone(id);
    }

    @Override
    public String getAlgorithm()
    {
        return "SM2 Key Exchange";
    }

    @Override
    public String getFormat()
    {
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        return new byte[0];
    }

    public PublicKey getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public PublicKey getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }

    public byte[] getId()
    {
        return Arrays.clone(id);
    }
}
