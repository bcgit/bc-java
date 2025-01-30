package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class SAKKEPrivateKey
    extends AsymmetricKeyParameter
{
    private final BigInteger b; // User's identity
    private final ECPoint K;    // Private key K_a
    private final SAKKEPublicKey publicParams;

    public SAKKEPrivateKey(BigInteger b, ECPoint K, SAKKEPublicKey publicParams)
    {
        super(true);
        this.b = b;
        this.K = K;
        this.publicParams = publicParams;
    }

    // Getters
    public ECPoint getK()
    {
        return K;
    }

    public BigInteger getB()
    {
        return b;
    }

    public SAKKEPublicKey getPublicParams()
    {
        return publicParams;
    }
}
