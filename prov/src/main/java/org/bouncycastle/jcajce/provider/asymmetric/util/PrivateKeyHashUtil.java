package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.interfaces.GOST3410Params;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

/**
 * Hash codes for private keys derived from public parameters and the derived public value.
 */
public final class PrivateKeyHashUtil
{
    private PrivateKeyHashUtil()
    {
    }

    public static int dsaHashCode(DSAParams params, BigInteger x)
    {
        if (params == null)
        {
            return 0;
        }

        BigInteger y = params.getG().modPow(x, params.getP());

        return y.hashCode() ^ params.getG().hashCode()
            ^ params.getP().hashCode() ^ params.getQ().hashCode();
    }

    public static int dhHashCode(DHParameterSpec params, BigInteger x)
    {
        BigInteger y = params.getG().modPow(x, params.getP());

        return y.hashCode() ^ params.getG().hashCode()
            ^ params.getP().hashCode() ^ params.getL();
    }

    public static int elGamalHashCode(ElGamalParameterSpec params, BigInteger x)
    {
        BigInteger y = params.getG().modPow(x, params.getP());

        return y.hashCode() ^ params.getP().hashCode() ^ params.getG().hashCode();
    }

    public static int gostHashCode(GOST3410Params params, BigInteger x)
    {
        GOST3410PublicKeyParameterSetSpec p = params.getPublicKeyParameters();
        BigInteger y = p.getA().modPow(x, p.getP());

        return y.hashCode() ^ params.hashCode();
    }

    public static int rsaHashCode(BigInteger modulus, BigInteger publicExponent)
    {
        return modulus.hashCode() ^ publicExponent.hashCode();
    }
}
