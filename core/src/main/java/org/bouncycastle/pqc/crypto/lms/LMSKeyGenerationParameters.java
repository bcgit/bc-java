package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class LMSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final LMSParameters lmsParam;
    private final LmOtsParameters lmOTSParam;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random   the random byte source.
     * @param strength the size, in bits, of the keys we want to produce.
     */
    public LMSKeyGenerationParameters(SecureRandom random, LMSParameters lmsParam, LmOtsParameters lmOTSParam)
    {
        super(random, 128);
        this.lmsParam = lmsParam;
        this.lmOTSParam = lmOTSParam;
    }

    public LMSParameters getLmsParam()
    {
        return lmsParam;
    }

    public LmOtsParameters getLmOTSParam()
    {
        return lmOTSParam;
    }
}
