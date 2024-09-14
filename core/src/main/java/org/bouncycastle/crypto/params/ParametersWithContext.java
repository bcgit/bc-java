package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

public class ParametersWithContext
    implements CipherParameters
{
    private CipherParameters  parameters;
    private byte[] context;

    public ParametersWithContext(
        CipherParameters parameters,
        byte[] context)
    {
        this.parameters = parameters;
        this.context = Arrays.clone(context);
    }

    public byte[] getContext()
    {
        return Arrays.clone(context);
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
