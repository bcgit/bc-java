package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class RSAPrivateCrtKeyParameters
    extends RSAKeyParameters
{
    private BigInteger  e;
    private BigInteger  p;
    private BigInteger  q;
    private BigInteger  dP;
    private BigInteger  dQ;
    private BigInteger  qInv;

    /**
     * 
     */
    public RSAPrivateCrtKeyParameters(
         BigInteger  modulus,
         BigInteger  publicExponent,
         BigInteger  privateExponent,
         BigInteger  p,
         BigInteger  q,
         BigInteger  dP,
         BigInteger  dQ,
         BigInteger  qInv)
     {
         this(modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv, false);
     }

    public RSAPrivateCrtKeyParameters(
        BigInteger  modulus,
        BigInteger  publicExponent,
        BigInteger  privateExponent,
        BigInteger  p,
        BigInteger  q,
        BigInteger  dP,
        BigInteger  dQ,
        BigInteger  qInv,
        boolean     isInternal)
    {
        super(true, modulus, privateExponent, isInternal);

        this.e = publicExponent;
        this.p = p;
        this.q = q;
        this.dP = dP;
        this.dQ = dQ;
        this.qInv = qInv;
    }

    public BigInteger getPublicExponent()
    {
        return e;
    }

    public BigInteger getP()
    {
        return valueWithCheck(p);
    }

    public BigInteger getQ()
    {
        return valueWithCheck(q);
    }

    public BigInteger getDP()
    {
        return valueWithCheck(dP);
    }

    public BigInteger getDQ()
    {
        return valueWithCheck(dQ);
    }

    public BigInteger getQInv()
    {
        return valueWithCheck(qInv);
    }

    /**
     * Destroy this object, dropping its references to the CRT factors and exponents along with
     * the inherited private exponent. The (public) modulus and public exponent are retained.
     * <p>
     * As {@link BigInteger} is immutable the values cannot be zeroized in place; destruction
     * drops the internal references so the values become unreachable (cleared on garbage
     * collection). After destruction the secret-bearing accessors throw
     * {@link IllegalStateException}.
     */
    public synchronized void destroy()
    {
        super.destroy();

        this.p = null;
        this.q = null;
        this.dP = null;
        this.dQ = null;
        this.qInv = null;
    }
}
