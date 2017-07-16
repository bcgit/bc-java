package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class ParametersWithUKM
    implements CipherParameters
{
    private byte[] ukm;
    private CipherParameters    parameters;

    public ParametersWithUKM(
        CipherParameters    parameters,
        byte[] ukm)
    {
        this(parameters, ukm, 0, ukm.length);
    }

    public ParametersWithUKM(
        CipherParameters    parameters,
        byte[] ukm,
        int                 ivOff,
        int                 ivLen)
    {
        this.ukm = new byte[ivLen];
        this.parameters = parameters;

        System.arraycopy(ukm, ivOff, this.ukm, 0, ivLen);
    }

    public byte[] getUKM()
    {
        return ukm;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
