package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class MLDSAKeyParameters
    extends AsymmetricKeyParameter
{
    private final MLDSAParameters params;

    private final byte[] context;

    public MLDSAKeyParameters(boolean isPrivate, MLDSAParameters params, byte[] context)
    {
        super(isPrivate);
        this.params = params;
        this.context = context;
    }

    public MLDSAKeyParameters(
        boolean isPrivate,
        MLDSAParameters params)
    {
        super(isPrivate);
        this.params = params;
        this.context = new byte[0];
    }

    public MLDSAParameters getParameters()
    {
        return params;
    }

    public byte[] getContext()
    {
        return context.clone();
    }
}
