package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/**
 * Basic config for Diffie-Hellman.
 */
public class TlsDHConfig
{
    protected BigInteger[] explicitPG;

    /**
     * Return the (p, g) values used in Diffie-Hellman.
     *
     * @return (p, g) as a BigInteger array (p=[0], g =[1]).
     */
    public BigInteger[] getExplicitPG()
    {
        return explicitPG.clone();
    }

    /**
     * Set the (p, g) values used in Diffie-Hellman.
     *
     * @param explicitPG (p, g) as a BigInteger array (p=[0], g =[1]).
     */
    public void setExplicitPG(BigInteger[] explicitPG)
    {
        this.explicitPG = explicitPG.clone();
    }
}
