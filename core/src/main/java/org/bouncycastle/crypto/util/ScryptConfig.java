package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;

/**
 * Configuration class for a PBKDF based around scrypt.
 */
public class ScryptConfig
    extends PBKDFConfig
{
    public static class Builder
    {
        private final int costParameter;
        private final int blockSize;
        private final int parallelizationParameter;

        private int saltLength = 16;

        /**
         * Base constructor.
         *
         * @param costParameter cost parameter (must be a power of 2)
         * @param blockSize block size
         * @param parallelizationParameter parallelization parameter
         */
        public Builder(int costParameter, int blockSize, int parallelizationParameter)
        {
            if (costParameter <= 1 || !isPowerOf2(costParameter))
            {
                throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
            }

            this.costParameter = costParameter;
            this.blockSize = blockSize;
            this.parallelizationParameter = parallelizationParameter;
        }

        /**
         * Set the length of the salt to use.
         *
         * @param saltLength the length of the salt (in octets) to use.
         * @return the current builder.
         */
        public Builder withSaltLength(int saltLength)
        {
            this.saltLength = saltLength;

            return this;
        }

        public ScryptConfig build()
        {
            return new ScryptConfig(this);
        }

        // note: we know X is non-zero
        private static boolean isPowerOf2(int x)
        {
            return ((x & (x - 1)) == 0);
        }
    }

    private final int costParameter;
    private final int blockSize;
    private final int parallelizationParameter;
    private final int saltLength;

    private ScryptConfig(Builder builder)
    {
        super(MiscObjectIdentifiers.id_scrypt);

        this.costParameter = builder.costParameter;
        this.blockSize = builder.blockSize;
        this.parallelizationParameter = builder.parallelizationParameter;
        this.saltLength = builder.saltLength;
    }

    public int getCostParameter()
    {
        return costParameter;
    }

    public int getBlockSize()
    {
        return blockSize;
    }

    public int getParallelizationParameter()
    {
        return parallelizationParameter;
    }

    public int getSaltLength()
    {
        return saltLength;
    }
}
