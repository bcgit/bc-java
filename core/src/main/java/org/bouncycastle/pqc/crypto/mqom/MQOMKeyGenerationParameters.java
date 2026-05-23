package org.bouncycastle.pqc.crypto.mqom;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class MQOMKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MQOMParameters params;

    public MQOMKeyGenerationParameters(SecureRandom random, MQOMParameters mqomParameters)
    {
        super(random, mqomParameters.getSecurityBits());
        this.params = mqomParameters;
    }

    public MQOMParameters getParameters()
    {
        return params;
    }
}
