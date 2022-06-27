package org.bouncycastle.pqc.crypto.sike;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SIKEKeyParameters
    extends AsymmetricKeyParameter
{
    private SIKEParameters params;

    public SIKEKeyParameters(
            boolean isPrivate,
            SIKEParameters params
    )
    {
        super(isPrivate);
        this.params = params;
    }

    public SIKEParameters getParameters()
    {
        return params;
    }
}
