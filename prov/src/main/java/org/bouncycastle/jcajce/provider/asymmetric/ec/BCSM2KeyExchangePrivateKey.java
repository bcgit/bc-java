package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.security.PrivateKey;

import org.bouncycastle.util.Arrays;

public class BCSM2KeyExchangePrivateKey
    implements PrivateKey
{
    private final boolean initiator;
    private PrivateKey staticPrivateKey;
    private PrivateKey ephemeralPrivateKey;

    public BCSM2KeyExchangePrivateKey(boolean initiator, PrivateKey staticPrivateKey, PrivateKey ephemeralPrivateKey)
    {
        this.initiator = initiator;
        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
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

    public boolean isInitiator()
    {
        return initiator;
    }

    public PrivateKey getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public PrivateKey getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }
}
