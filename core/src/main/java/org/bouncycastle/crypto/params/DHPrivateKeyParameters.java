package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DHPrivateKeyParameters
    extends DHKeyParameters
{
    private BigInteger      x;

    public DHPrivateKeyParameters(
        BigInteger      x,
        DHParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }

    public int hashCode()
    {
        DHParameters params = getParameters();
        BigInteger y = params.getG().modPow(x, params.getP());

        return y.hashCode() ^ super.hashCode();
    }
    
    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHPrivateKeyParameters))
        {
            return false;
        }

        DHPrivateKeyParameters  other = (DHPrivateKeyParameters)obj;

        return other.getX().equals(this.x) && super.equals(obj);
    }
}
