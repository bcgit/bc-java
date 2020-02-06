package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import java.util.Collection;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class HSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final LMSParameters[] lmsParameters;

    public HSSKeyGenerationParameters(
        LMSParameters[] lmsParameters,
        SecureRandom random)
    {
        super(random, 128);   // TODO: need to calculate based on lmsParameters

        if (lmsParameters == null)
        {
            throw new IllegalArgumentException("lms parameters are null");
        }

        this.lmsParameters = lmsParameters;
    }

    public static Builder builder(int depth)
    {
        return new Builder(depth);
    }

    public int getDepth()
    {
        return lmsParameters.length;
    }

    public LMSParameters[] getLmsParameters()
    {
        return lmsParameters;
    }


    public static class Builder
    {
        private int depth;
        private LMSParameters[] lmsParameters;
        private SecureRandom lmsEntropySource;
        private byte[] masterSeed;
        private int strength;

        public Builder(int depth)
        {
            this.depth = depth;
        }

        public Builder setDepth(int depth)
        {
            this.depth = depth;
            return this;
        }


        public Builder setLmsParameters(LMSParameters... lmsParameters)
        {
            this.lmsParameters = lmsParameters;
            return this;
        }

        public Builder setLmsParameters(Collection<LMSParameters> lmsParameters)
        {
            this.lmsParameters = lmsParameters.toArray(new LMSParameters[lmsParameters.size()]);
            return this;
        }

        public Builder setStrength(int strength)
        {
            this.strength = strength;
            return this;
        }

        public Builder setLmsEntropySource(SecureRandom lmsEntropySource)
        {
            if (this.masterSeed != null)
            {
                throw new IllegalArgumentException("attempting to set entropy source after setting master seed.");
            }

            this.lmsEntropySource = lmsEntropySource;
            return this;
        }


        public Builder setLmsEntropySource(byte[] masterSeed)
        {
            if (this.lmsEntropySource != null)
            {
                throw new IllegalArgumentException("attempting to set master seed while entropy source is not null");
            }
            this.masterSeed = masterSeed;
            return this;
        }


        public HSSKeyGenerationParameters build()
        {
            return new HSSKeyGenerationParameters(lmsParameters, lmsEntropySource);
        }

    }


}
