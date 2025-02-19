package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.ECPoint;

public class ECCSIPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final ECPoint pvt;

    public ECCSIPublicKeyParameters(ECPoint pvt)
    {
        super(false);
        this.pvt = pvt;
    }

    public final ECPoint getPVT()
    {
        return pvt;
    }
}
