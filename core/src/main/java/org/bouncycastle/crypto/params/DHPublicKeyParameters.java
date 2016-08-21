package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DHPublicKeyParameters
    extends DHKeyParameters
{
    private BigInteger      y;

    public DHPublicKeyParameters(
        BigInteger      y,
        DHParameters    params)
    {
        super(false, params);

        this.y = validate(y, params);
    }   

    private BigInteger validate(BigInteger y, DHParameters dhParams)
    {
        if (dhParams.getQ() != null)
        {
            if (BigInteger.ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
            {
                return y;
            }

            throw new IllegalArgumentException("Y value does not appear to be in correct group");
        }
        else
        {
            return y;         // we can't validate without Q.
        }
    }

    public BigInteger getY()
    {
        return y;
    }

    public int hashCode()
    {
        return y.hashCode() ^ super.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHPublicKeyParameters))
        {
            return false;
        }

        DHPublicKeyParameters   other = (DHPublicKeyParameters)obj;

        return other.getY().equals(y) && super.equals(obj);
    }
}
