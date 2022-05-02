package org.bouncycastle.pqc.crypto.picnic;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class PicnicKeyParameters
    extends AsymmetricKeyParameter
{

    final PicnicParameters parameters;

    public PicnicKeyParameters(boolean isPrivate, PicnicParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }
    public PicnicParameters getParameters()
    {
        return parameters;
    }
}
