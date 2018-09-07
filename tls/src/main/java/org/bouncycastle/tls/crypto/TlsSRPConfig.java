package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/**
 * Basic config for SRP.
 */
public class TlsSRPConfig
{
    protected BigInteger[] explicitNG;

    /**
     * Return the (N, g) values used in SRP-6.
     *
     * @return (N, g) as a BigInteger array (N=[0], g =[1]).
     */
    public BigInteger[] getExplicitNG()
    {
        return (BigInteger[])explicitNG.clone();
    }

    /**
     * Set the (N, g) values used for SRP-6.
     *
     * @param explicitNG (N, g) as a BigInteger array (N=[0], g =[1]).
     */
    public void setExplicitNG(BigInteger[] explicitNG)
    {
        this.explicitNG = (BigInteger[])explicitNG.clone();
    }
}
