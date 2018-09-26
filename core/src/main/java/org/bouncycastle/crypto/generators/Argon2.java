package org.bouncycastle.crypto.generators;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;


/**
 * Based on the java implementation by Andreas Gadermaier
 * <p>
 * https://github.com/andreas1327250/argon2-java
 * <p>
 * Original license:
 * <p>
 * MIT License
 * <p>
 * Copyright (c) 2017 Andreas Gadermaier
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

public class Argon2
{

    private static final int ARGON2_BLOCK_SIZE = 1024;
    private static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

    private static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

    private static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;
    private static final int ARGON2_PREHASH_SEED_LENGTH = 72;

    private static final int ARGON2_SYNC_POINTS = 4;

    public static final int ARGON2_VERSION_10 = 0x10;
    public static final int ARGON2_VERSION_13 = 0x13;


    public static final int DEFAULT_OUTPUTLEN = 32;
    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_MEMORY_COST = 12;
    private static final int DEFAULT_LANES = 1;
    private static final ArgonType DEFAULT_TYPE = ArgonType.Argon2i;
    private static final int DEFAULT_VERSION = ARGON2_VERSION_13;

    /* Minimum and maximum number of lanes (degree of parallelism) */
    private static final int MIN_PARALLELISM = 1;
    private static final int MAX_PARALLELISM = 16777216;

    /* Minimum and maximum digest size in bytes */
    private static final int MIN_OUTLEN = 4;

    /* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
    private static final int MIN_MEMORY = (2 * ARGON2_SYNC_POINTS); /* 2 blocks per slice */

    /* Minimum and maximum number of passes */
    private static final int MIN_ITERATIONS = 1;


    public enum ArgonType
    {
        Argon2d, Argon2i, Argon2id
    }


    public Block[] memory;


    private int segmentLength;
    private int laneLength;


    private Argon2Parameters parameters;

    private byte[] result;

    /**
     * Create a new Argon2 digest instance from the parameters.
     *
     * @param parameters
     */
    public Argon2(Argon2Parameters parameters)
    {
        this.parameters = parameters;


        if (parameters.getLanes() < Argon2.MIN_PARALLELISM)
        {
            throw new IllegalStateException("Lanes must be greater than " + Argon2.MIN_PARALLELISM);
        }
        else if (parameters.getLanes() > Argon2.MAX_PARALLELISM)
        {
            throw new IllegalStateException("Lanes must be less than " + Argon2.MAX_PARALLELISM);
        }
        else if (parameters.getMemory() < 2 * parameters.getLanes())
        {
            throw new IllegalStateException("Memory is less than: " + (2 * parameters.getLanes()) + " expected " + (2 * parameters.getLanes()));
        }
        else if (parameters.getIterations() < Argon2.MIN_ITERATIONS)
        {
            throw new IllegalStateException("Iterations is less than: " + Argon2.MIN_ITERATIONS);
        }

        init();
    }

    // Generate the hash.
    public int generate(byte[] out, int outOff)
    {
        int outputLength = out.length - outOff;

        if (outputLength < Argon2.MIN_OUTLEN)
        {
            throw new IllegalStateException("Output length less than " + Argon2.MIN_OUTLEN);
        }

        initialize(outputLength);
        fillMemoryBlocks();
        digest(outputLength);
        System.arraycopy(result, 0, out, outOff, out.length);

        return out.length;
    }

    // Clear memory.
    public void clear()
    {
        // Reset memory.
        for (Block b : memory)
        {
            b.clear();
        }
        memory = null;
        Arrays.fill(result, (byte)0);
        init();
    }

    private void init()
    {
        /* 2. Align memory size */
        /* Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
        int memoryBlocks = parameters.getMemory();

        if (memoryBlocks < 2 * Argon2.ARGON2_SYNC_POINTS * parameters.getLanes())
        {
            memoryBlocks = 2 * Argon2.ARGON2_SYNC_POINTS * parameters.getLanes();
        }

        this.segmentLength = memoryBlocks / (parameters.getLanes() * Argon2.ARGON2_SYNC_POINTS);
        this.laneLength = segmentLength * Argon2.ARGON2_SYNC_POINTS;

        /* Ensure that all segments have equal length */
        memoryBlocks = segmentLength * (parameters.getLanes() * Argon2.ARGON2_SYNC_POINTS);

        initMemory(memoryBlocks);
    }


    private void initMemory(int memoryBlocks)
    {
        this.memory = new Block[memoryBlocks];

        for (int i = 0; i < memory.length; i++)
        {
            memory[i] = new Block();
        }
    }

    protected Block[] getMemory()
    {
        return memory;
    }


    private void fillBlock(Block X, Block Y, Block currentBlock, boolean withXor)
    {

        Block R = new Block();
        Block Z = new Block();

        R.xor(X, Y);
        Z.copyBlock(R);

        /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
        (16,17,..31)... finally (112,113,...127) */
        for (int i = 0; i < 8; i++)
        {

            roundFunction(Z,
                16 * i, 16 * i + 1, 16 * i + 2,
                16 * i + 3, 16 * i + 4, 16 * i + 5,
                16 * i + 6, 16 * i + 7, 16 * i + 8,
                16 * i + 9, 16 * i + 10, 16 * i + 11,
                16 * i + 12, 16 * i + 13, 16 * i + 14,
                16 * i + 15
            );
        }

        /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
        (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
        for (int i = 0; i < 8; i++)
        {

            roundFunction(Z,
                2 * i, 2 * i + 1, 2 * i + 16,
                2 * i + 17, 2 * i + 32, 2 * i + 33,
                2 * i + 48, 2 * i + 49, 2 * i + 64,
                2 * i + 65, 2 * i + 80, 2 * i + 81,
                2 * i + 96, 2 * i + 97, 2 * i + 112,
                2 * i + 113
            );

        }

        if (withXor)
        {
            currentBlock.xor(R, Z, currentBlock);
        }
        else
        {
            currentBlock.xor(R, Z);
        }

    }

    private void fillMemoryBlocks()
    {
        for (int i = 0; i < parameters.getIterations(); i++)
        {
            for (int j = 0; j < ARGON2_SYNC_POINTS; j++)
            {
                for (int k = 0; k < parameters.getLanes(); k++)
                {
                    Position position = new Position(i, k, j, 0);
                    fillSegment(position);
                }
            }
        }
    }

    private void fillSegment(Position position)
    {

        Block addressBlock = null, inputBlock = null, zeroBlock = null;

        boolean dataIndependentAddressing = isDataIndependentAddressing(position);
        int startingIndex = getStartingIndex(position);
        int currentOffset = position.lane * laneLength + position.slice * segmentLength + startingIndex;
        int prevOffset = getPrevOffset(currentOffset);

        if (dataIndependentAddressing)
        {
            addressBlock = new Block();
            zeroBlock = new Block();
            inputBlock = new Block();

            initAddressBlocks(position, zeroBlock, inputBlock, addressBlock);
        }

        for (position.index = startingIndex; position.index < segmentLength; position.index++, currentOffset++, prevOffset++)
        {
            prevOffset = rotatePrevOffset(currentOffset, prevOffset);

            long pseudoRandom = getPseudoRandom(position, addressBlock, inputBlock, zeroBlock, prevOffset, dataIndependentAddressing);
            int refLane = getRefLane(position, pseudoRandom);
            int refColumn = getRefColumn(position, pseudoRandom, refLane == position.lane);

            /* 2 Creating a new block */
            Block prevBlock = memory[prevOffset];
            Block refBlock = memory[((laneLength) * refLane + refColumn)];
            Block currentBlock = memory[currentOffset];

            boolean withXor = isWithXor(position);
            fillBlock(prevBlock, refBlock, currentBlock, withXor);
        }
    }

    private boolean isDataIndependentAddressing(Position position)
    {
        return (parameters.getType() == ArgonType.Argon2i) ||
            (parameters.getType() == ArgonType.Argon2id
                && (position.pass == 0)
                && (position.slice < ARGON2_SYNC_POINTS / 2)
            );
    }

    private void initAddressBlocks(Position position, Block zeroBlock, Block inputBlock, Block addressBlock)
    {
        inputBlock.v[0] = intToLong(position.pass);
        inputBlock.v[1] = intToLong(position.lane);
        inputBlock.v[2] = intToLong(position.slice);
        inputBlock.v[3] = intToLong(memory.length);
        inputBlock.v[4] = intToLong(parameters.getIterations());
        inputBlock.v[5] = intToLong(parameters.getType().ordinal());

        if ((position.pass == 0) && (position.slice == 0))
        {
            /* Don't forget to generate the first block of addresses: */
            nextAddresses(zeroBlock, inputBlock, addressBlock);
        }
    }

    private boolean isWithXor(Position position)
    {
        return !(position.pass == 0 || parameters.getVersion() == ARGON2_VERSION_10);
    }

    private int getPrevOffset(int currentOffset)
    {
        if (currentOffset % laneLength == 0)
        {
            /* Last block in this lane */
            return currentOffset + laneLength - 1;
        }
        else
        {
            /* Previous block */
            return currentOffset - 1;
        }
    }

    private int rotatePrevOffset(int currentOffset, int prevOffset)
    {
        if (currentOffset % laneLength == 1)
        {
            prevOffset = currentOffset - 1;
        }
        return prevOffset;
    }

    private static int getStartingIndex(Position position)
    {
        if ((position.pass == 0) && (position.slice == 0))
        {
            return 2; /* we have already generated the first two blocks */
        }
        else
        {
            return 0;
        }
    }

    private void nextAddresses(Block zeroBlock, Block inputBlock, Block addressBlock)
    {
        inputBlock.v[6]++;
        fillBlock(zeroBlock, inputBlock, addressBlock, false);
        fillBlock(zeroBlock, addressBlock, addressBlock, false);
    }

    /* 1.2 Computing the index of the reference block */
    /* 1.2.1 Taking pseudo-random value from the previous block */
    private long getPseudoRandom(Position position, Block addressBlock, Block inputBlock, Block zeroBlock, int prevOffset, boolean dataIndependentAddressing)
    {
        if (dataIndependentAddressing)
        {
            if (position.index % ARGON2_ADDRESSES_IN_BLOCK == 0)
            {
                nextAddresses(zeroBlock, inputBlock, addressBlock);
            }
            return addressBlock.v[position.index % ARGON2_ADDRESSES_IN_BLOCK];
        }
        else
        {
            return memory[prevOffset].v[0];
        }
    }

    private int getRefLane(Position position, long pseudoRandom)
    {
        int refLane = (int)(((pseudoRandom >>> 32)) % parameters.getLanes());

        if ((position.pass == 0) && (position.slice == 0))
        {
            /* Can not reference other lanes yet */
            refLane = position.lane;
        }
        return refLane;
    }

    private int getRefColumn(Position position, long pseudoRandom,
                             boolean sameLane)
    {

        int referenceAreaSize;
        int startPosition;

        if (position.pass == 0)
        {
            startPosition = 0;

            if (sameLane)
            {
                /* The same lane => add current segment */
                referenceAreaSize = position.slice * segmentLength + position.index - 1;
            }
            else
            {
                /* pass == 0 && !sameLane => position.slice > 0*/
                referenceAreaSize = position.slice * segmentLength + ((position.index == 0) ? (-1) : 0);
            }

        }
        else
        {
            startPosition = ((position.slice + 1) * segmentLength) % laneLength;

            if (sameLane)
            {
                referenceAreaSize = laneLength - segmentLength + position.index - 1;
            }
            else
            {
                referenceAreaSize = laneLength - segmentLength + ((position.index == 0) ? (-1) : 0);
            }
        }

        long relativePosition = pseudoRandom & 0xFFFFFFFFL;
//        long relativePosition = pseudoRandom << 32 >>> 32;
        relativePosition = (relativePosition * relativePosition) >>> 32;
        relativePosition = referenceAreaSize - 1 - (referenceAreaSize * relativePosition >>> 32);

        return (int)(startPosition + relativePosition) % laneLength;
    }

    private void digest(int outputLength)
    {

        Block finalBlock = memory[laneLength - 1];

        /* XOR the last blocks */
        for (int i = 1; i < parameters.getLanes(); i++)
        {
            int lastBlockInLane = i * laneLength + (laneLength - 1);
            finalBlock.xorWith(memory[lastBlockInLane]);
        }

        byte[] finalBlockBytes = finalBlock.toBytes();
        byte[] finalResult = blake2bLong(finalBlockBytes, outputLength);

        result = finalResult;
    }

    /**
     * H0 = H64(p, τ, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
     * -> 64 byte (ARGON2_PREHASH_DIGEST_LENGTH)
     */
    private byte[] initialHash(byte[] lanes, byte[] outputLength,
                               byte[] memory, byte[] iterations,
                               byte[] version, byte[] type,
                               byte[] passwordLength, byte[] password,
                               byte[] saltLength, byte[] salt,
                               byte[] secretLength, byte[] secret,
                               byte[] additionalLength, byte[] additional)
    {


        Blake2bDigest blake = new Blake2bDigest(ARGON2_PREHASH_DIGEST_LENGTH * 8);


        updateIfNotNull(blake, lanes);


        updateIfNotNull(blake, outputLength);
        updateIfNotNull(blake, memory);
        updateIfNotNull(blake, iterations);
        updateIfNotNull(blake, version);
        updateIfNotNull(blake, type);

        updateIfNotNull(blake, passwordLength);

        updateIfNotNull(blake, password);

        updateIfNotNull(blake, saltLength);

        updateIfNotNull(blake, salt);


        updateIfNotNull(blake, secretLength);

        updateIfNotNull(blake, secret);


        updateIfNotNull(blake, additionalLength);

        updateIfNotNull(blake, additional);


        byte[] blake2hash = new byte[blake.getDigestSize()];
        blake.doFinal(blake2hash, 0);

        return blake2hash;
    }

    /**
     * H' - blake2bLong - variable length hash function
     */
    private byte[] blake2bLong(byte[] input, int outputLength)
    {

        assert (input.length == ARGON2_PREHASH_SEED_LENGTH || input.length == ARGON2_BLOCK_SIZE);

        byte[] result = new byte[outputLength];
        byte[] outlenBytes = Pack.intToLittleEndian(outputLength);

        int blake2bLength = 64;

        if (outputLength <= blake2bLength)
        {
            result = blake2b(input, outlenBytes, outputLength);
        }
        else
        {
            byte[] outBuffer;

            /* V1 */
            outBuffer = blake2b(input, outlenBytes, blake2bLength);
            System.arraycopy(outBuffer, 0, result, 0, blake2bLength / 2);

            int r = (outputLength / 32) + (outputLength % 32 == 0 ? 0 : 1) - 2;

            int position = blake2bLength / 2;
            for (int i = 2; i <= r; i++, position += blake2bLength / 2)
            {
                /* V2 to Vr */
                outBuffer = blake2b(outBuffer, null, blake2bLength);
                System.arraycopy(outBuffer, 0, result, position, blake2bLength / 2);
            }

            int lastLength = outputLength - 32 * r;

            /* Vr+1 */
            outBuffer = blake2b(outBuffer, null, lastLength);
            System.arraycopy(outBuffer, 0, result, position, lastLength);
        }

        assert (result.length == outputLength);
        return result;
    }

    private byte[] blake2b(byte[] input, byte[] outlenBytes, int outputLength)
    {

        Blake2bDigest blake = new Blake2bDigest(outputLength * 8);

        updateIfNotNull(blake, outlenBytes);
        updateIfNotNull(blake, input);

        byte[] out = new byte[outputLength];
        blake.doFinal(out, 0);
        return out;
    }

    private void roundFunction(Block block,
                               int v0, int v1, int v2, int v3,
                               int v4, int v5, int v6, int v7,
                               int v8, int v9, int v10, int v11,
                               int v12, int v13, int v14, int v15)
    {

        F(block, v0, v4, v8, v12);
        F(block, v1, v5, v9, v13);
        F(block, v2, v6, v10, v14);
        F(block, v3, v7, v11, v15);

        F(block, v0, v5, v10, v15);
        F(block, v1, v6, v11, v12);
        F(block, v2, v7, v8, v13);
        F(block, v3, v4, v9, v14);
    }

    private void F(Block block, int a, int b, int c, int d)
    {
        fBlaMka(block, a, b);
        rotr64(block, d, a, 32);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 24);

        fBlaMka(block, a, b);
        rotr64(block, d, a, 16);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 63);
    }

    /*designed by the Lyra PHC team */
    /* a <- a + b + 2*aL*bL
     * + == addition modulo 2^64
     * aL = least 32 bit */
    private void fBlaMka(Block block, int x, int y)
    {
        final long m = 0xFFFFFFFFL;
        final long xy = (block.v[x] & m) * (block.v[y] & m);

        block.v[x] = block.v[x] + block.v[y] + 2 * xy;
    }

    private void rotr64(Block block, int v, int w, long c)
    {
        final long temp = block.v[v] ^ block.v[w];
        block.v[v] = (temp >>> c) | (temp << (64 - c));
    }

    private void initialize(int outputLength)
    {


        byte[] initialHash = initialHash(
            Pack.intToLittleEndian(parameters.getLanes()),
            Pack.intToLittleEndian(outputLength),
            Pack.intToLittleEndian(parameters.getMemory()),
            Pack.intToLittleEndian(parameters.getIterations()),
            Pack.intToLittleEndian(parameters.getVersion()),
            Pack.intToLittleEndian(parameters.getType().ordinal()),
            Pack.intToLittleEndian(lengthZeroIfNull(parameters.getPassword())),
            parameters.getPassword(),
            Pack.intToLittleEndian(lengthZeroIfNull(parameters.getSalt())),
            parameters.getSalt(),
            Pack.intToLittleEndian(lengthZeroIfNull(parameters.getSecret())),
            parameters.getSecret(),
            Pack.intToLittleEndian(lengthZeroIfNull(parameters.getAdditional())),
            parameters.getAdditional()
        );
        fillFirstBlocks(initialHash);
    }


    private int lengthZeroIfNull(byte[] src)
    {
        if (src == null)
        {
            return 0;
        }
        return src.length;
    }


    /**
     * (H0 || 0 || i) 72 byte -> 1024 byte
     * (H0 || 1 || i) 72 byte -> 1024 byte
     */
    private void fillFirstBlocks(byte[] initialHash)
    {

        final byte[] zeroBytes = {0, 0, 0, 0};
        final byte[] oneBytes = {1, 0, 0, 0};

        byte[] initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes);
        byte[] initialHashWithOnes = getInitialHashLong(initialHash, oneBytes);

        for (int i = 0; i < parameters.getLanes(); i++)
        {

            byte[] iBytes = Pack.intToLittleEndian(i);

            System.arraycopy(iBytes, 0, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);
            System.arraycopy(iBytes, 0, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);

            byte[] blockhashBytes = blake2bLong(initialHashWithZeros, ARGON2_BLOCK_SIZE);
            memory[i * laneLength + 0].fromBytes(blockhashBytes);

            blockhashBytes = blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE);
            memory[i * laneLength + 1].fromBytes(blockhashBytes);
        }
    }

    private byte[] getInitialHashLong(byte[] initialHash, byte[] appendix)
    {
        byte[] initialHashLong = new byte[ARGON2_PREHASH_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_PREHASH_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_PREHASH_DIGEST_LENGTH, 4);

        return initialHashLong;
    }


    private long intToLong(int x)
    {
        byte[] bytes = new byte[8];
        Pack.intToLittleEndian(x, bytes, 0);
        return Pack.littleEndianToLong(bytes, 0);
    }


    private void updateIfNotNull(Digest digest, byte[] value)
    {
        if (value == null)
        {
            return;
        }
        digest.update(value, 0, value.length);
    }

    public static class Block
    {

        /* 128 * 8 Byte QWords */
        private long[] v;

        private Block()
        {
            v = new long[ARGON2_QWORDS_IN_BLOCK];
        }

        public void fromBytes(byte[] input)
        {
            if (input.length != ARGON2_BLOCK_SIZE)
            {
                throw new IllegalArgumentException("Input shorter than blocksize");
            }

            for (int i = 0; i < v.length; i++)
            {
                byte[] slice = Arrays.copyOfRange(input, i * 8, (i + 1) * 8);
                v[i] = Pack.littleEndianToLong(slice, 0);
            }
        }

        public byte[] toBytes()
        {
            byte[] result = new byte[ARGON2_BLOCK_SIZE];

            for (int i = 0; i < v.length; i++)
            {
                byte[] bytes = Pack.longToLittleEndian(v[i]);
                System.arraycopy(bytes, 0, result, i * bytes.length, bytes.length);
            }

            return result;
        }

        private void copyBlock(Block other)
        {
            System.arraycopy(other.v, 0, v, 0, v.length);
        }

        private void xor(Block b1, Block b2)
        {
            for (int i = 0; i < v.length; i++)
            {
                v[i] = b1.v[i] ^ b2.v[i];
            }
        }

        public void xor(Block b1, Block b2, Block b3)
        {
            for (int i = 0; i < v.length; i++)
            {
                v[i] = b1.v[i] ^ b2.v[i] ^ b3.v[i];
            }
        }

        private void xorWith(Block other)
        {
            for (int i = 0; i < v.length; i++)
            {
                v[i] = v[i] ^ other.v[i];
            }
        }

        @Override
        public String toString()
        {
            StringBuilder result = new StringBuilder();
            for (long value : v)
            {
                result.append(Hex.toHexString(Pack.longToLittleEndian(value)));
            }

            return result.toString();
        }

        public void clear()
        {
            Arrays.fill(v, 0);
        }
    }

    private static class Position
    {
        public int pass;
        public int lane;
        public int slice;
        public int index;

        public Position(int pass, int lane, int slice, int index)
        {
            this.pass = pass;
            this.lane = lane;
            this.slice = slice;
            this.index = index;
        }
    }


    public static Argon2ParametersBuilder builder()
    {
        return new Argon2ParametersBuilder();
    }

    public static Argon2ParametersBuilder builder(ArgonType type)
    {
        return new Argon2ParametersBuilder(type);
    }


    protected static class Argon2Parameters
    {
        private final byte[] salt;
        private final byte[] secret;
        private final byte[] additional;

        private final int iterations;
        private final int memory;
        private final int lanes;

        private final int version;
        private final byte[] password;
        private final ArgonType type;

        protected Argon2Parameters(
            byte[] salt,
            byte[] secret,
            byte[] additional,
            int iterations,
            int memory,
            int lanes,
            int version,
            byte[] password, ArgonType type)
        {

            this.salt = salt;
            this.secret = secret;
            this.additional = additional;
            this.iterations = iterations;
            this.memory = memory;
            this.lanes = lanes;
            this.version = version;
            this.password = password;
            this.type = type;
        }


        public byte[] getSalt()
        {
            return salt;
        }

        public byte[] getSecret()
        {
            return secret;
        }

        public byte[] getAdditional()
        {
            return additional;
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

        public ArgonType getType()
        {
            return type;
        }

        public byte[] getPassword()
        {
            return password;
        }
    }


    public static class Argon2ParametersBuilder
    {

        private byte[] salt;
        private byte[] secret;
        private byte[] additional;

        private int iterations; // -t N
        private int memory; // -m N
        private int lanes; // -p N

        private int version; // -v (10/13)
        private final ArgonType type;

        private ByteArrayOutputStream password = new ByteArrayOutputStream();

        private Charset charset = Charset.forName("UTF-8");


        private Argon2ParametersBuilder(ArgonType type)
        {
            this.type = type;
            this.lanes = DEFAULT_LANES;
            this.memory = 1 << DEFAULT_MEMORY_COST;
            this.iterations = DEFAULT_ITERATIONS;
            this.version = DEFAULT_VERSION;
        }

        private Argon2ParametersBuilder()
        {
            this(DEFAULT_TYPE);
        }


        public void clear()
        {

            if (salt != null)
            {
                Arrays.fill(salt, 0, salt.length - 1, (byte)0);
            }

            if (secret != null)
            {
                Arrays.fill(secret, 0, secret.length - 1, (byte)0);
            }

            if (additional != null)
            {
                Arrays.fill(additional, 0, additional.length - 1, (byte)0);
            }
        }


        public Argon2ParametersBuilder setMemoryInKiB(int memory)
        {
            this.memory = memory;
            return this;
        }

        public Argon2ParametersBuilder withParallelism(int parallelism)
        {
            this.lanes = parallelism;
            return this;
        }


        public Argon2ParametersBuilder withSalt(String salt)
        {
            this.salt = Strings.toByteArray(salt, charset);
            return this;
        }


        public byte[] getSalt()
        {
            return salt;
        }

        public Argon2ParametersBuilder withSalt(byte[] salt)
        {
            this.salt = salt;
            return this;
        }

        public int getSaltLength()
        {
            return salt.length;
        }

        public byte[] getSecret()
        {
            return secret;
        }

        public Argon2ParametersBuilder withSecret(byte[] secret)
        {
            this.secret = secret;
            return this;
        }

        public int getSecretLength()
        {
            return secret != null ? secret.length : 0;
        }

        public byte[] getAdditional()
        {
            return additional;
        }

        public Argon2ParametersBuilder withAdditional(byte[] additional)
        {
            this.additional = additional;
            return this;
        }

        public int getAdditionalLength()
        {
            return additional != null ? additional.length : 0;
        }

        public int getIterations()
        {
            return iterations;
        }

        public Argon2ParametersBuilder withIterations(int iterations)
        {
            this.iterations = iterations;
            return this;
        }

        public int getMemory()
        {
            return memory;
        }

        public Argon2ParametersBuilder withMemory(int memory)
        {
            this.memory = memory;
            return this;
        }


        public Argon2ParametersBuilder withMemoryPowOfTwo(int memory)
        {
            this.memory = 1 << memory;
            return this;
        }

        public int getLanes()
        {
            return lanes;
        }

        public int getVersion()
        {
            return version;
        }

        public Argon2ParametersBuilder withVersion(int version)
        {
            this.version = version;
            return this;
        }

        public ArgonType getType()
        {
            return type;
        }

        public Charset getCharset()
        {
            return charset;
        }

        public Argon2ParametersBuilder withCharSet(Charset set)
        {
            this.charset = set;
            return this;
        }


        public Argon2Parameters build()
        {
            return new Argon2Parameters(salt, secret, additional, iterations, memory, lanes, version, password.toByteArray(), type);
        }

        public byte[] encodeString(String value)
        {
            return Strings.toByteArray(value, charset);
        }

        public OutputStream getPasswordOutputStream()
        {
            return password;
        }


    }


}
