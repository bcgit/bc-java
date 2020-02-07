package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class HSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final LMSParameters[] lmsParameters;


    public HSSKeyGenerationParameters(
        LMSParameters[] lmsParameters,
        SecureRandom random)
    {
        super(random, LmsUtils.calculateStrength(lmsParameters[0]));
        this.lmsParameters = lmsParameters;
    }


    public int getDepth()
    {
        return lmsParameters.length;
    }

    public LMSParameters[] getLmsParameters()
    {
        return lmsParameters;
    }


}
