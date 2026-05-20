package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator.BlockPool;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * Configuration parameters for the {@link org.bouncycastle.crypto.generators.Argon2BytesGenerator Argon2 PBKDF}.
 * <p>
 * Build instances with {@link Builder}, e.g.
 * <pre>
 * Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
 *     .withVersion(Argon2Parameters.ARGON2_VERSION_13)
 *     .withSalt(salt)
 *     .withIterations(3)
 *     .withMemoryPowOfTwo(16)
 *     .withParallelism(4)
 *     .build();
 * </pre>
 */
public class Argon2Parameters
{
    /**
     * System/security property setting the maximum permitted memory exponent
     * (i.e. {@code memory <= 1 << MAX_MEMORY_EXP}). Default and ceiling are 30.
     */
    public static final String MAX_MEMORY_EXP = "org.bouncycastle.argon2.max_memory_exp";

    /** Argon2d - data-dependent memory access. */
    public static final int ARGON2_d = 0x00;
    /** Argon2i - data-independent memory access. */
    public static final int ARGON2_i = 0x01;
    /** Argon2id - hybrid of {@link #ARGON2_i} and {@link #ARGON2_d}. */
    public static final int ARGON2_id = 0x02;

    /** Argon2 v1.0 (legacy). */
    public static final int ARGON2_VERSION_10 = 0x10;
    /** Argon2 v1.3 - the version standardised by RFC 9106. */
    public static final int ARGON2_VERSION_13 = 0x13;

    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_MEMORY_COST = 12;
    private static final int DEFAULT_LANES = 1;
    private static final int DEFAULT_TYPE = ARGON2_i;
    private static final int DEFAULT_VERSION = ARGON2_VERSION_13;

    /**
     * Fluent builder for {@link Argon2Parameters}.
     */
    public static class Builder
    {
        private byte[] salt;
        private byte[] secret;
        private byte[] additional;

        private int iterations;
        private int memory;
        private int lanes;

        private int version;
        private final int type;
        private final int maxMemory;
        
        private CharToByteConverter converter = PasswordConverter.UTF8;

        private BlockPool blockPool;

        /**
         * Create a builder defaulting to {@link Argon2Parameters#ARGON2_i}.
         */
        public Builder()
        {
            this(DEFAULT_TYPE);
        }

        /**
         * Create a builder for the given Argon2 variant.
         *
         * @param type one of {@link Argon2Parameters#ARGON2_d}, {@link Argon2Parameters#ARGON2_i},
         *             or {@link Argon2Parameters#ARGON2_id}.
         */
        public Builder(int type)
        {
            this.type = type;
            this.lanes = DEFAULT_LANES;
            this.memory = 1 << DEFAULT_MEMORY_COST;
            this.iterations = DEFAULT_ITERATIONS;
            this.version = DEFAULT_VERSION;
            this.maxMemory = Properties.asInteger(MAX_MEMORY_EXP, 30);
            if (maxMemory < 3  || maxMemory > 30)
            {
                throw new IllegalStateException(MAX_MEMORY_EXP + " out of range");
            }
        }

        /**
         * Set the parallelism (number of lanes).
         *
         * @param parallelism the degree of parallelism, must be at least 1.
         * @return this builder.
         */
        public Builder withParallelism(int parallelism)
        {
            if (lanes < 1)
            {
                throw new IllegalArgumentException("lanes out of range");
            }
            this.lanes = parallelism;
            return this;
        }

        /**
         * Set the salt. The supplied array is defensively cloned.
         *
         * @param salt salt bytes; may be null.
         * @return this builder.
         */
        public Builder withSalt(byte[] salt)
        {
            this.salt = Arrays.clone(salt);
            return this;
        }

        /**
         * Set the optional secret (key) value. The supplied array is defensively cloned.
         *
         * @param secret secret bytes; may be null.
         * @return this builder.
         */
        public Builder withSecret(byte[] secret)
        {
            this.secret = Arrays.clone(secret);
            return this;
        }

        /**
         * Set the optional additional/associated data. The supplied array is defensively cloned.
         *
         * @param additional additional data bytes; may be null.
         * @return this builder.
         */
        public Builder withAdditional(byte[] additional)
        {
            this.additional = Arrays.clone(additional);
            return this;
        }

        /**
         * Set the number of passes (time cost).
         *
         * @param iterations number of iterations, must be at least 1.
         * @return this builder.
         */
        public Builder withIterations(int iterations)
        {
            this.iterations = iterations;
            return this;
        }

        /**
         * Set the memory cost expressed directly in KiB.
         *
         * @param memory memory in KiB; must be in {@code [1, 1 << MAX_MEMORY_EXP]}.
         * @return this builder.
         * @throws IllegalArgumentException if the value is out of range.
         */
        public Builder withMemoryAsKB(int memory)
        {
            if (memory < 1 || memory > (1 << maxMemory))
            {
                throw new IllegalArgumentException("memory out of range");
            }
            this.memory = memory;
            return this;
        }

        /**
         * Set the memory cost as a power of two: the resulting memory in KiB is {@code 1 << memory}.
         *
         * @param memory exponent; must be in {@code [0, MAX_MEMORY_EXP]}.
         * @return this builder.
         * @throws IllegalArgumentException if the exponent is out of range.
         */
        public Builder withMemoryPowOfTwo(int memory)
        {
            // Actual range is supposed to be 31 - int's are signed here so cutoff is at 2**30
            if (memory < 0 || memory > maxMemory)
            {
                throw new IllegalArgumentException("memory exponent out of range");
            }
            this.memory = 1 << memory;
            return this;
        }

        /**
         * Set the Argon2 version.
         *
         * @param version one of {@link Argon2Parameters#ARGON2_VERSION_10} or {@link Argon2Parameters#ARGON2_VERSION_13}.
         * @return this builder.
         */
        public Builder withVersion(int version)
        {
            this.version = version;
            return this;
        }

        /**
         * Override the converter used to turn {@code char[]} passwords into bytes.
         * Default is {@link PasswordConverter#UTF8}.
         *
         * @param converter the character-to-byte converter to use.
         * @return this builder.
         */
        public Builder withCharToByteConverter(CharToByteConverter converter)
        {
            this.converter = converter;
            return this;
        }

        /**
         * Provide a custom {@link BlockPool} for the generator to source its
         * working blocks from. Useful in high-throughput scenarios where the
         * cost of allocating fresh {@code long[]} buffers per call dominates.
         * If null (the default) the generator creates a per-call FixedBlockPool.
         */
        public Builder withBlockPool(BlockPool blockPool)
        {
            this.blockPool = blockPool;
            return this;
        }

        /**
         * Construct an immutable {@link Argon2Parameters} from the current builder state.
         *
         * @return the configured parameters.
         */
        public Argon2Parameters build()
        {
            return new Argon2Parameters(type, salt, secret, additional, iterations, memory, lanes, version, converter, blockPool);
        }

        /**
         * Zeroise sensitive state (salt, secret, additional) held by this builder.
         */
        public void clear()
        {
            Arrays.clear(salt);
            Arrays.clear(secret);
            Arrays.clear(additional);
        }
    }

    private final byte[] salt;
    private final byte[] secret;
    private final byte[] additional;

    private final int iterations;
    private final int memory;
    private final int lanes;

    private final int version;
    private final int type;
    private final CharToByteConverter converter;
    private final BlockPool blockPool;

    private Argon2Parameters(
        int type,
        byte[] salt,
        byte[] secret,
        byte[] additional,
        int iterations,
        int memory,
        int lanes,
        int version,
        CharToByteConverter converter,
        BlockPool blockPool)
    {

        this.salt = Arrays.clone(salt);
        this.secret = Arrays.clone(secret);
        this.additional = Arrays.clone(additional);
        this.iterations = iterations;
        this.memory = memory;
        this.lanes = lanes;
        this.version = version;
        this.type = type;
        this.converter = converter;
        this.blockPool = blockPool;
    }

    /**
     * @return a defensive copy of the salt, or null if none was set.
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /**
     * @return a defensive copy of the secret value, or null if none was set.
     */
    public byte[] getSecret()
    {
        return Arrays.clone(secret);
    }

    /**
     * @return a defensive copy of the additional data, or null if none was set.
     */
    public byte[] getAdditional()
    {
        return Arrays.clone(additional);
    }

    /**
     * @return the number of passes (time cost).
     */
    public int getIterations()
    {
        return iterations;
    }

    /**
     * @return the memory cost in KiB.
     */
    public int getMemory()
    {
        return memory;
    }

    /**
     * @return the parallelism (lane count).
     */
    public int getLanes()
    {
        return lanes;
    }

    /**
     * @return the Argon2 version constant ({@link #ARGON2_VERSION_10} or {@link #ARGON2_VERSION_13}).
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * @return the Argon2 variant constant ({@link #ARGON2_d}, {@link #ARGON2_i}, or {@link #ARGON2_id}).
     */
    public int getType()
    {
        return type;
    }

    /**
     * @return the character-to-byte converter used to encode {@code char[]} passwords.
     */
    public CharToByteConverter getCharToByteConverter()
    {
        return converter;
    }

    /**
     * @return the user-supplied {@link BlockPool}, or null if the generator should use its default per-call pool.
     */
    public BlockPool getBlockPool()
    {
        return blockPool;
    }

    /**
     * Zeroise sensitive state (salt, secret, additional) held by these parameters.
     */
    public void clear()
    {
        Arrays.clear(salt);
        Arrays.clear(secret);
        Arrays.clear(additional);
    }
}
