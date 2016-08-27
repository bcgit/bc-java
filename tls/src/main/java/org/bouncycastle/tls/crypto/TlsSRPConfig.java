package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

public class TlsSRPConfig
{
    protected BigInteger[] explicitNG;

    public BigInteger[] getExplicitNG()
    {
        return explicitNG;
    }

    public void setExplicitNG(BigInteger[] explicitNG)
    {
        this.explicitNG = explicitNG;
    }
}
