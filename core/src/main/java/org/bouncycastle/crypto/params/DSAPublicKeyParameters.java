package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class DSAPublicKeyParameters
    extends DSAKeyParameters
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private BigInteger      y;

    public DSAPublicKeyParameters(
        BigInteger      y,
        DSAParameters   params)
    {
        super(false, params);

        this.y = validate(y, params);
    }   

    private BigInteger validate(BigInteger y, DSAParameters params)
    {
        if (params != null)
        {
            if (TWO.compareTo(y) <= 0 && params.getP().subtract(TWO).compareTo(y) >= 0
                && ONE.equals(y.modPow(params.getQ(), params.getP())))
            {
                return y;
            }

            throw new IllegalArgumentException("y value does not appear to be in correct group");
        }
        else
        {
            return y;         // we can't validate without params, fortunately we can't use the key either...
        }
    }

    public BigInteger getY()
    {
        return y;
    }
}
