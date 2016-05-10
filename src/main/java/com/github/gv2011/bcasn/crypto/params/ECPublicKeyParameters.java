package com.github.gv2011.bcasn.crypto.params;

import com.github.gv2011.bcasn.math.ec.ECPoint;

public class ECPublicKeyParameters
    extends ECKeyParameters
{
    ECPoint Q;

    public ECPublicKeyParameters(
        ECPoint             Q,
        ECDomainParameters  params)
    {
        super(false, params);
        this.Q = Q.normalize();
    }

    public ECPoint getQ()
    {
        return Q;
    }
}
