package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class ParametersWithSBoxIV implements CipherParameters
{
    private CipherParameters parameters;
    private byte[]            sBox;
    private byte[]              iv;

    public ParametersWithSBoxIV(
            CipherParameters parameters,
            byte[]           sBox,
            byte[]              iv)
    {
        this.parameters = parameters;
        this.sBox = sBox;
        this.iv = iv;
    }

    public byte[] getSBox()
    {
        return sBox;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }

    public byte[] getIV()
    {
        return iv;
    }
}
