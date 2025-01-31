package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

public class SAKKEPublicKey
    extends AsymmetricKeyParameter
{
    private final ECCurve curve = new SecP256R1Curve();
    private final ECPoint P;  // Base point
    private final ECPoint Z;  // KMS Public Key: Z = [z]P
    private final BigInteger q; // Subgroup order
    private final int n;      // SSV bit length

    public SAKKEPublicKey(ECPoint P, ECPoint Z, BigInteger q, int n)
    {
        super(false);
        this.P = P;
        this.Z = Z;
        this.q = q;
        this.n = n;
    }

    // Getters
    public ECCurve getCurve()
    {
        return curve;
    }

    public ECPoint getP()
    {
        return P;
    }

    public ECPoint getZ()
    {
        return Z;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getN()
    {
        return n;
    }
}
