package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class FalconKeyParameters
    extends AsymmetricKeyParameter
{

    private FalconParameters param;

    public FalconKeyParameters(boolean isprivate, FalconParameters param)
    {
        super(isprivate);
        this.param = param;
    }

    public FalconParameters getParam()
    {
        return param;
    }
}
