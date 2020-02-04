package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import java.util.Collection;

public class HSSKeyGenerationParameters
{
    private final int depth;
    private final LmsParameter[] lmsParameters;
    private final LmOtsParameter[] lmOtsParameters;
    private final SecureRandom lmsEntropySource;
    private final byte[] masterSeed;


    private HSSKeyGenerationParameters(
        int depth,
        LmsParameter[] lmsParameters,
        LmOtsParameter[] lmOtsParameters,
        SecureRandom lmsEntropySource, boolean generateOTSPK,
        byte[] masterSeed)
    {
        this.depth = depth;
        this.lmsParameters = lmsParameters;
        this.lmOtsParameters = lmOtsParameters;
        this.lmsEntropySource = lmsEntropySource;
        this.masterSeed = masterSeed;
    }

    public static Builder builder(int depth)
    {
        return new Builder(depth);
    }

    public int getDepth()
    {
        return depth;
    }

    public LmsParameter[] getLmsParameters()
    {
        return lmsParameters;
    }

    public LmOtsParameter[] getLmOtsParameters()
    {
        return lmOtsParameters;
    }

    public SecureRandom getLmsEntropySource()
    {
        return lmsEntropySource;
    }


    public byte[] getMasterSeed()
    {
        return masterSeed;
    }

    public static class Builder
    {
        private int depth;
        private LmsParameter[] lmsParameters;
        private LmOtsParameter[] lmOtsParameters;
        private SecureRandom lmsEntropySource;
        private byte[] masterSeed;
        private boolean generateOTSPK;

        public Builder(int depth)
        {
            this.depth = depth;
        }

        public Builder setDepth(int depth)
        {
            this.depth = depth;
            return this;
        }


        public Builder setLmsParameters(LmsParameter... lmsParameters)
        {
            this.lmsParameters = lmsParameters;
            return this;
        }

        public Builder setLmsParameters(Collection<LmsParameter> lmsParameters)
        {
            this.lmsParameters = lmsParameters.toArray(new LmsParameter[lmsParameters.size()]);
            return this;
        }


        public Builder generateOTSPK(boolean preGenerate)
        {
            generateOTSPK = preGenerate;
            return this;
        }


        public Builder setLmsParameters(int... lmsType)
            throws LMSException
        {
            lmsParameters = new LmsParameter[lmsType.length];
            int c = 0;
            for (int t : lmsType)
            {
                lmsParameters[c++] = LMSParameters.getParametersForType(t);
            }

            return this;
        }


        public Builder setLmOtsParameters(int... lmOtsType)
            throws LMSException
        {
            lmOtsParameters = new LmOtsParameter[lmOtsType.length];
            int c = 0;
            for (int t : lmOtsType)
            {
                lmOtsParameters[c++] = LmOtsParameters.getOtsParameter(t);
            }

            return this;
        }


        public Builder setLmOtsParameters(LmOtsParameter... lmOtsParameters)
        {
            this.lmOtsParameters = lmOtsParameters;
            return this;
        }

        public Builder setLmOtsParameters(Collection<LmOtsParameter> lmOtsParameters)
        {
            this.lmOtsParameters = lmOtsParameters.toArray(new LmOtsParameter[lmOtsParameters.size()]);
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

            if (depth < 1)
            {
                throw new IllegalStateException("depth less than 1");
            }

            if (lmsParameters == null)
            {
                throw new IllegalStateException("lms parameters are null");
            }

            if (lmOtsParameters == null)
            {
                throw new IllegalStateException("lmOts parameters are null");
            }

            if (lmsEntropySource == null)
            {
                lmsEntropySource = new SecureRandom();
            }

            if (lmOtsParameters.length != depth)
            {
                throw new IllegalStateException("lmOts parameters length should match depth");
            }

            if (lmsParameters.length != depth)
            {
                throw new IllegalStateException("lms parameters length should match depth");
            }

            return new HSSKeyGenerationParameters(depth, lmsParameters, lmOtsParameters, lmsEntropySource, generateOTSPK, masterSeed);
        }

    }


}
