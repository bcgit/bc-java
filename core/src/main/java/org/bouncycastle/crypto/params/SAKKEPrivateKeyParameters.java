package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class SAKKEPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final SAKKEPublicKeyParameters publicParams;
    private final BigInteger z;  // KMS Public Key: Z = [z]P
    private final ECPoint rsk;

    public SAKKEPrivateKeyParameters(BigInteger z, ECPoint rsk, SAKKEPublicKeyParameters publicParams)
    {
        super(true);
        this.z = z;
        this.rsk = rsk;
        this.publicParams = publicParams;
    }

    public SAKKEPublicKeyParameters getPublicParams()
    {
        return publicParams;
    }


    public BigInteger getMasterSecret()
    {
        return z;
    }

    public ECPoint getRSK()
    {
        return rsk;
    }
}
