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

        this.Q = ECDomainParameters.validate(params.getCurve(), Q);
    }

    public ECPoint getQ()
    {
        return Q;
    }
}
