package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.PrivateKey;

import org.bouncycastle.util.Arrays;

public class BCSM2KeyExchangePrivateKey
    implements PrivateKey
{
    private final PrivateKey staticPrivateKey;
    private final PrivateKey ephemeralPrivateKey;
    private final byte[] id;

    public BCSM2KeyExchangePrivateKey(PrivateKey staticPrivateKey, PrivateKey ephemeralPrivateKey, byte[] id)
    {
        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.id = Arrays.clone(id);
    }

    @Override
    public String getAlgorithm()
    {
        return "SM2 KeyExchange Private";
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

    public PrivateKey getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

//    public ECPoint getStaticPublicPoint()
//    {
//        return staticPublicPoint;
//    }

    public PrivateKey getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public byte[] getId()
    {
        return Arrays.clone(id);
    }

//    public ECPoint getEphemeralPublicPoint()
//    {
//        return ephemeralPublicPoint;
//    }
}
