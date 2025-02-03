package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class SAKKEPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final BigInteger b; // User's identity
    private final ECPoint K;    // Private key K_a
    private final SAKKEPublicKeyParameters publicParams;

    public SAKKEPrivateKeyParameters(BigInteger b, ECPoint K, SAKKEPublicKeyParameters publicParams)
    {
        super(true);
        this.b = b;
        this.K = K;
        this.publicParams = publicParams;
    }

    public BigInteger getB()
    {
        return b;
    }

    public SAKKEPublicKeyParameters getPublicParams()
    {
        return publicParams;
    }

    public ECPoint getPrivatePoint()
    {
        return K;
    }
}
