package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SLHDSAKeyParameters
    extends AsymmetricKeyParameter
{
    final SLHDSAParameters parameters;
    final byte[] context;

    protected SLHDSAKeyParameters(boolean isPrivate, SLHDSAParameters parameters, byte[] context)
    {
        super(isPrivate);
        this.parameters = parameters;
        this.context = context;
    }

    protected SLHDSAKeyParameters(boolean isPrivate, SLHDSAParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
        this.context = new byte[0];
    }

    public SLHDSAParameters getParameters()
    {
        return parameters;
    }
    public byte[] getContext()
    {
        return context.clone();
    }
}
