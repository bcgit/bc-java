package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.ECPoint;

public class ECPublicKeyParameters
    extends ECKeyParameters
{
    private final ECPoint Q;

    public ECPublicKeyParameters(
        ECPoint             Q,
        ECDomainParameters  params)
    {
        super(false, params);

        this.Q = validate(Q);
    }

    private ECPoint validate(ECPoint q)
    {
        if (q == null)
        {
            throw new IllegalArgumentException("point has null value");
        }

        if (q.isInfinity())
        {
            throw new IllegalArgumentException("point at infinity");
        }

        q = q.normalize();

        if (!q.isValid())
        {
            throw new IllegalArgumentException("point not on curve");
        }

        return q;
    }

    public ECPoint getQ()
    {
        return Q;
    }
}
