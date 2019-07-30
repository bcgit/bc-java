package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class ECPrivateKeyParameters
    extends ECKeyParameters
{
    private final BigInteger d;

    public ECPrivateKeyParameters(
        BigInteger          d,
        ECDomainParameters  parameters)
    {
        super(true, parameters);

        this.d = parameters.validatePrivateScalar(d);
    }

    public BigInteger getD()
    {
        return d;
    }
}
