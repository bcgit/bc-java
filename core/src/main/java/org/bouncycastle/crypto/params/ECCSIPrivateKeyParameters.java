package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ECCSIPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final BigInteger ssk;
    public ECCSIPrivateKeyParameters(BigInteger ssk)
    {
        super(true);
        this.ssk = ssk;
    }
}
