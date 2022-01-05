package org.bouncycastle.pqc.crypto.cmce;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class CMCEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private CMCEParameters params;

    public CMCEKeyGenerationParameters(
        SecureRandom random,
        CMCEParameters cmceParams)
    {
        super(random, 256);
        this.params = cmceParams;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }
}
