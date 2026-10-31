package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @deprecated Now believed unsafe to use - will be removed in a future release.
 */
@Deprecated
public class CMCEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final CMCEParameters params;

    public CMCEKeyGenerationParameters(
        SecureRandom random,
        CMCEParameters cmceParameters)
    {
        super(random, 256);
        this.params = cmceParameters;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }
}
