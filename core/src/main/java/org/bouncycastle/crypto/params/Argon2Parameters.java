package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator.Block;
import org.bouncycastle.util.Arrays;

import java.util.concurrent.LinkedBlockingQueue;

public class Argon2Parameters
{
    public static interface BlockPool {
        Block allocate();
        void deallocate(Block block);
    }

    public static class FixedBlockPool implements BlockPool {

        private LinkedBlockingQueue<Block> blocks;

        public FixedBlockPool(int maxBlocks) {
            this.blocks = new LinkedBlockingQueue<>(maxBlocks);
        }

        @Override
        public Block allocate() {
            Block block = blocks.poll();
            if (block == null) {
                return new Block();
            }
            // since we're not tracking which thread deallocated
            // we don't know if the clearing is visible in this one
            block.clear();
            return block;
        }

        @Override
        public void deallocate(Block block) {
            block.clear();
            blocks.offer(block);
        }

    }

    public static final int ARGON2_d = 0x00;
    public static final int ARGON2_i = 0x01;
    public static final int ARGON2_id = 0x02;

    public static final int ARGON2_VERSION_10 = 0x10;
    public static final int ARGON2_VERSION_13 = 0x13;

    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_MEMORY_COST = 12;
    private static final int DEFAULT_LANES = 1;
    private static final int DEFAULT_TYPE = ARGON2_i;
    private static final int DEFAULT_VERSION = ARGON2_VERSION_13;

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

        private CharToByteConverter converter = PasswordConverter.UTF8;

        private BlockPool blockPool;

        public Builder()
        {
            this(DEFAULT_TYPE);
        }

        public Builder(int type)
        {
            this.type = type;
            this.lanes = DEFAULT_LANES;
            this.memory = 1 << DEFAULT_MEMORY_COST;
            this.iterations = DEFAULT_ITERATIONS;
            this.version = DEFAULT_VERSION;
        }

        public Builder withParallelism(int parallelism)
        {
            this.lanes = parallelism;
            return this;
        }

        public Builder withSalt(byte[] salt)
        {
            this.salt = Arrays.clone(salt);
            return this;
        }

        public Builder withSecret(byte[] secret)
        {
            this.secret = Arrays.clone(secret);
            return this;
        }

        public Builder withAdditional(byte[] additional)
        {
            this.additional = Arrays.clone(additional);
            return this;
        }

        public Builder withIterations(int iterations)
        {
            this.iterations = iterations;
            return this;
        }


        public Builder withMemoryAsKB(int memory)
        {
            this.memory = memory;
            return this;
        }


        public Builder withMemoryPowOfTwo(int memory)
        {
            this.memory = 1 << memory;
            return this;
        }

        public Builder withVersion(int version)
        {
            this.version = version;
            return this;
        }

        public Builder withCharToByteConverter(CharToByteConverter converter)
        {
            this.converter = converter;
            return this;
        }

        public Builder withBlockPool(BlockPool blockPool)
        {
            this.blockPool = blockPool;
            return this;
        }

        public Argon2Parameters build()
        {
            return new Argon2Parameters(type, salt, secret, additional, iterations, memory, lanes, version, converter, blockPool);
        }

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

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public byte[] getSecret()
    {
        return Arrays.clone(secret);
    }

    public byte[] getAdditional()
    {
        return Arrays.clone(additional);
    }

    public int getIterations()
    {
        return iterations;
    }

    public int getMemory()
    {
        return memory;
    }

    public int getLanes()
    {
        return lanes;
    }

    public int getVersion()
    {
        return version;
    }

    public int getType()
    {
        return type;
    }

    public CharToByteConverter getCharToByteConverter()
    {
        return converter;
    }

    public BlockPool getBlockPool() {
        return blockPool;
    }

    public void clear()
    {
        Arrays.clear(salt);
        Arrays.clear(secret);
        Arrays.clear(additional);
    }
}
