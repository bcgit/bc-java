package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ECCSIPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final BigInteger ssk;
    private final ECCSIPublicKeyParameters pub;

    public ECCSIPrivateKeyParameters(BigInteger ssk, ECCSIPublicKeyParameters pub)
    {
        super(true);
        this.ssk = ssk;
        this.pub = pub;
    }

    public ECCSIPublicKeyParameters getPublicKeyParameters()
    {
        return pub;
    }

    public BigInteger getSSK()
    {
        return ssk;
    }
}
