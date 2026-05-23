package org.bouncycastle.pqc.crypto.mqom;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class MQOMKeyParameters
    extends AsymmetricKeyParameter
{
    private final MQOMParameters params;

    public MQOMKeyParameters(boolean isPrivate, MQOMParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public MQOMParameters getParameters()
    {
        return params;
    }
}
