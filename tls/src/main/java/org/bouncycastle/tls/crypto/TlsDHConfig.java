package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

public class TlsDHConfig
{
    protected BigInteger[] explicitPG;

    public BigInteger[] getExplicitPG()
    {
        return explicitPG;
    }

    public void setExplicitPG(BigInteger[] explicitPG)
    {
        this.explicitPG = explicitPG;
    }
}
