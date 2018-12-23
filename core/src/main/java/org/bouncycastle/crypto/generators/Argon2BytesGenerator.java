package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;


/**
 * Argon2 PBKDF - Based on the results of https://password-hashing.net/ and https://www.ietf.org/archive/id/draft-irtf-cfrg-argon2-03.txt
 */
public class Argon2BytesGenerator
{

    private static final int ARGON2_BLOCK_SIZE = 1024;
    private static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

    private static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

    private static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;
    private static final int ARGON2_PREHASH_SEED_LENGTH = 72;

    private static final int ARGON2_SYNC_POINTS = 4;

    /* Minimum and maximum number of lanes (degree of parallelism) */
    private static final int MIN_PARALLELISM = 1;
    private static final int MAX_PARALLELISM = 16777216;

    /* Minimum and maximum digest size in bytes */
    private static final int MIN_OUTLEN = 4;
    
    /* Minimum and maximum number of passes */
    private static final int MIN_ITERATIONS = 1;

    private Block[] memory;


    private int segmentLength;
    private int laneLength;


    private Argon2Parameters parameters;

    private byte[] result;

    public Argon2BytesGenerator()
    {

    }

    /**
     * Initialise the Argon2BytesGenerator from the parameters.
     *
     * @param parameters Argon2 configuration.
     */
    public void init(Argon2Parameters parameters)
    {
        this.parameters = parameters;


        if (parameters.getLanes() < Argon2BytesGenerator.MIN_PARALLELISM)
        {
            throw new IllegalStateException("lanes must be greater than " + Argon2BytesGenerator.MIN_PARALLELISM);
        }
        else if (parameters.getLanes() > Argon2BytesGenerator.MAX_PARALLELISM)
        {
            throw new IllegalStateException("lanes must be less than " + Argon2BytesGenerator.MAX_PARALLELISM);
        }
        else if (parameters.getMemory() < 2 * parameters.getLanes())
        {
            throw new IllegalStateException("memory is less than: " + (2 * parameters.getLanes()) + " expected " + (2 * parameters.getLanes()));
        }
        else if (parameters.getIterations() < Argon2BytesGenerator.MIN_ITERATIONS)
        {
            throw new IllegalStateException("iterations is less than: " + Argon2BytesGenerator.MIN_ITERATIONS);
        }

        doInit(parameters);
    }

    public int generateBytes(char[] password, byte[] out)
    {
        return generateBytes(parameters.getCharToByteConverter().convert(password), out);
    }

    public int generateBytes(char[] password, byte[] out, int outOff, int outLen)
    {
        return generateBytes(parameters.getCharToByteConverter().convert(password), out, outOff, outLen);
    }

    public int generateBytes(byte[] password, byte[] out)
    {
        return generateBytes(password, out, 0, out.length);
    }

    public int generateBytes(byte[] password, byte[] out, int outOff, int outLen)
    {
        if (outLen < Argon2BytesGenerator.MIN_OUTLEN)
        {
            throw new IllegalStateException("output length less than " + Argon2BytesGenerator.MIN_OUTLEN);
        }

        initialize(password, outLen);
        fillMemoryBlocks();
        digest(outLen);

        System.arraycopy(result, 0, out, outOff, outLen);

        reset();

        return outLen;
    }

    // Clear memory.
    private void reset()
    {
        // Reset memory.
        for (int i = 0; i < memory.length; i++)
        {
            Block b = memory[i];

            b.clear();
        }
        memory = null;
        Arrays.fill(result, (byte)0);
        doInit(parameters);
    }

    private void doInit(Argon2Parameters parameters)
    {
        /* 2. Align memory size */
        /* Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
        int memoryBlocks = parameters.getMemory();

        if (memoryBlocks < 2 * Argon2BytesGenerator.ARGON2_SYNC_POINTS * parameters.getLanes())
        {
            memoryBlocks = 2 * Argon2BytesGenerator.ARGON2_SYNC_POINTS * parameters.getLanes();
        }

        this.segmentLength = memoryBlocks / (parameters.getLanes() * Argon2BytesGenerator.ARGON2_SYNC_POINTS);
        this.laneLength = segmentLength * Argon2BytesGenerator.ARGON2_SYNC_POINTS;

        /* Ensure that all segments have equal length */
        memoryBlocks = segmentLength * (parameters.getLanes() * Argon2BytesGenerator.ARGON2_SYNC_POINTS);

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
        return (parameters.getType() == Argon2Parameters.ARGON2_i) ||
            (parameters.getType() == Argon2Parameters.ARGON2_id
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
        inputBlock.v[5] = intToLong(parameters.getType());

        if ((position.pass == 0) && (position.slice == 0))
        {
            /* Don't forget to generate the first block of addresses: */
            nextAddresses(zeroBlock, inputBlock, addressBlock);
        }
    }

    private boolean isWithXor(Position position)
    {
        return !(position.pass == 0 || parameters.getVersion() == Argon2Parameters.ARGON2_VERSION_10);
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
        relativePosition = referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) >>> 32);

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

        result = hash(finalBlockBytes, outputLength);
    }

    /**
     * H0 = H64(p, τ, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
     * -> 64 byte (ARGON2_PREHASH_DIGEST_LENGTH)
     */
    private byte[] initialHash(Argon2Parameters parameters, int outputLength, byte[] password)
    {
        Blake2bDigest blake = new Blake2bDigest(ARGON2_PREHASH_DIGEST_LENGTH * 8);

        addIntToLittleEndian(blake, parameters.getLanes());
        addIntToLittleEndian(blake, outputLength);
        addIntToLittleEndian(blake, parameters.getMemory());
        addIntToLittleEndian(blake, parameters.getIterations());
        addIntToLittleEndian(blake, parameters.getVersion());
        addIntToLittleEndian(blake, parameters.getType());

        addByteString(blake, password);
        addByteString(blake, parameters.getSalt());
        addByteString(blake, parameters.getSecret());
        addByteString(blake, parameters.getAdditional());

        byte[] blake2hash = new byte[blake.getDigestSize()];
        blake.doFinal(blake2hash, 0);

        return blake2hash;
    }

    /**
     * H' - hash - variable length hash function
     */
    private byte[] hash(byte[] input, int outputLength)
    {
        byte[] result = new byte[outputLength];
        byte[] outlenBytes = Pack.intToLittleEndian(outputLength);

        int blake2bLength = 64;

        if (outputLength <= blake2bLength)
        {
            Blake2bDigest blake = new Blake2bDigest(outputLength * 8);

            blake.update(outlenBytes, 0, outlenBytes.length);
            blake.update(input, 0, input.length);
            blake.doFinal(result, 0);
        }
        else
        {
            Blake2bDigest digest = new Blake2bDigest(blake2bLength * 8);
            byte[] outBuffer = new byte[blake2bLength];

            /* V1 */
            digest.update(outlenBytes, 0, outlenBytes.length);
            digest.update(input, 0, input.length);
            digest.doFinal(outBuffer, 0);

            System.arraycopy(outBuffer, 0, result, 0, blake2bLength / 2);

            int r = ((outputLength + 31) / 32) - 2;

            int position = blake2bLength / 2;

            for (int i = 2; i <= r; i++, position += blake2bLength / 2)
            {
                /* V2 to Vr */
                digest.update(outBuffer, 0, outBuffer.length);
                digest.doFinal(outBuffer, 0);

                System.arraycopy(outBuffer, 0, result, position, blake2bLength / 2);
            }

            int lastLength = outputLength - 32 * r;

            /* Vr+1 */
            digest = new Blake2bDigest(lastLength * 8);

            digest.update(outBuffer, 0, outBuffer.length);
            digest.doFinal(result, position);
        }

        return result;
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

    private void initialize(byte[] password, int outputLength)
    {
        byte[] initialHash = initialHash(parameters, outputLength, password);
        
        fillFirstBlocks(initialHash);
    }

    private static void addIntToLittleEndian(Digest digest, int n)
    {
        digest.update((byte)(n       ));
        digest.update((byte)(n >>>  8));
        digest.update((byte)(n >>> 16));
        digest.update((byte)(n >>> 24));
    }

    private static void addByteString(Digest digest, byte[] octets)
    {
        if (octets != null)
        {
            addIntToLittleEndian(digest, octets.length);
            digest.update(octets, 0, octets.length);
        }
        else
        {
            addIntToLittleEndian(digest, 0);
        }
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
            Pack.intToLittleEndian(i, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
            Pack.intToLittleEndian(i, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

            byte[] blockhashBytes = hash(initialHashWithZeros, ARGON2_BLOCK_SIZE);
            memory[i * laneLength + 0].fromBytes(blockhashBytes);

            blockhashBytes = hash(initialHashWithOnes, ARGON2_BLOCK_SIZE);
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
        return (long)(x & 0xffffffffL);
    }
    
    private static class Block
    {
        /* 128 * 8 Byte QWords */
        private long[] v;

        private Block()
        {
            v = new long[ARGON2_QWORDS_IN_BLOCK];
        }

        void fromBytes(byte[] input)
        {
            if (input.length != ARGON2_BLOCK_SIZE)
            {
                throw new IllegalArgumentException("input shorter than blocksize");
            }

            for (int i = 0; i < v.length; i++)
            {
                v[i] = Pack.littleEndianToLong(input, i * 8);
            }
        }

        byte[] toBytes()
        {
            byte[] result = new byte[ARGON2_BLOCK_SIZE];

            for (int i = 0; i < v.length; i++)
            {
                Pack.longToLittleEndian(v[i], result, i * 8);
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
        
        public String toString()
        {
            StringBuffer result = new StringBuffer();
            for (int i = 0; i < v.length; i++)
            {
                result.append(Hex.toHexString(Pack.longToLittleEndian(v[i])));
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
        int pass;
        int lane;
        int slice;
        int index;

        Position(int pass, int lane, int slice, int index)
        {
            this.pass = pass;
            this.lane = lane;
            this.slice = slice;
            this.index = index;
        }
    }
}
