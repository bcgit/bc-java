package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class MLDSAKeyParameters
    extends AsymmetricKeyParameter
{
    private final MLDSAParameters params;

    public MLDSAKeyParameters(
        boolean isPrivate,
        MLDSAParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public MLDSAParameters getParameters()
    {
        return params;
    }
}
