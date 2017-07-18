package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;

/**
 * implementation of Keccak based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class KeccakDigest
    implements ExtendedDigest
{
    private static long[] KeccakRoundConstants = keccakInitializeRoundConstants();

    private static int[] KeccakRhoOffsets = keccakInitializeRhoOffsets();

    private static long[] keccakInitializeRoundConstants()
    {
        long[] keccakRoundConstants = new long[24];
        byte[] LFSRstate = new byte[1];

        LFSRstate[0] = 0x01;
        int i, j, bitPosition;

        for (i = 0; i < 24; i++)
        {
            keccakRoundConstants[i] = 0;
            for (j = 0; j < 7; j++)
            {
                bitPosition = (1 << j) - 1;
                if (LFSR86540(LFSRstate))
                {
                    keccakRoundConstants[i] ^= 1L << bitPosition;
                }
            }
        }

        return keccakRoundConstants;
    }

    private static boolean LFSR86540(byte[] LFSR)
    {
        boolean result = (((LFSR[0]) & 0x01) != 0);
        if (((LFSR[0]) & 0x80) != 0)
        {
            LFSR[0] = (byte)(((LFSR[0]) << 1) ^ 0x71);
        }
        else
        {
            LFSR[0] <<= 1;
        }

        return result;
    }

    private static int[] keccakInitializeRhoOffsets()
    {
        int[] keccakRhoOffsets = new int[25];
        int x, y, t, newX, newY;

        keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = 0;
        x = 1;
        y = 0;
        for (t = 0; t < 24; t++)
        {
            keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = ((t + 1) * (t + 2) / 2) % 64;
            newX = (0 * x + 1 * y) % 5;
            newY = (2 * x + 3 * y) % 5;
            x = newX;
            y = newY;
        }
        return keccakRhoOffsets;
    }

    protected byte[] state = new byte[(1600 / 8)];
    protected byte[] dataQueue = new byte[(1536 / 8)];
    protected int rate;
    protected int bitsInQueue;
    protected int fixedOutputLength;
    protected boolean squeezing;
    protected int bitsAvailableForSqueezing;
    protected byte[] chunk;
    protected byte[] oneByte;

    private void clearDataQueueSection(int off, int len)
    {
        for (int i = off; i != off + len; i++)
        {
            dataQueue[i] = 0;
        }
    }

    public KeccakDigest()
    {
        this(288);
    }

    public KeccakDigest(int bitLength)
    {
        init(bitLength);
    }

    public KeccakDigest(KeccakDigest source) {
        System.arraycopy(source.state, 0, this.state, 0, source.state.length);
        System.arraycopy(source.dataQueue, 0, this.dataQueue, 0, source.dataQueue.length);
        this.rate = source.rate;
        this.bitsInQueue = source.bitsInQueue;
        this.fixedOutputLength = source.fixedOutputLength;
        this.squeezing = source.squeezing;
        this.bitsAvailableForSqueezing = source.bitsAvailableForSqueezing;
        this.chunk = Arrays.clone(source.chunk);
        this.oneByte = Arrays.clone(source.oneByte);
    }

    public String getAlgorithmName()
    {
        return "Keccak-" + fixedOutputLength;
    }

    public int getDigestSize()
    {
        return fixedOutputLength / 8;
    }

    public void update(byte in)
    {
        oneByte[0] = in;

        absorb(oneByte, 0, 8L);
    }

    public void update(byte[] in, int inOff, int len)
    {
        absorb(in, inOff, len * 8L);
    }

    public int doFinal(byte[] out, int outOff)
    {
        squeeze(out, outOff, fixedOutputLength);

        reset();

        return getDigestSize();
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits)
    {
        if (partialBits > 0)
        {
            oneByte[0] = partialByte;
            absorb(oneByte, 0, partialBits);
        }

        squeeze(out, outOff, fixedOutputLength);

        reset();

        return getDigestSize();
    }

    public void reset()
    {
        init(fixedOutputLength);
    }

    /**
     * Return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    public int getByteLength()
    {
        return rate / 8;
    }

    private void init(int bitLength)
    {
        switch (bitLength)
        {
        case 288:
            initSponge(1024, 576);
            break;
        case 128:
            initSponge(1344, 256);
            break;
        case 224:
            initSponge(1152, 448);
            break;
        case 256:
            initSponge(1088, 512);
            break;
        case 384:
            initSponge(832, 768);
            break;
        case 512:
            initSponge(576, 1024);
            break;
        default:
            throw new IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
        }
    }

    private void initSponge(int rate, int capacity)
    {
        if (rate + capacity != 1600)
        {
            throw new IllegalStateException("rate + capacity != 1600");
        }
        if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
        {
            throw new IllegalStateException("invalid rate value");
        }

        this.rate = rate;
        // this is never read, need to check to see why we want to save it
        //  this.capacity = capacity;
        Arrays.fill(this.state, (byte)0);
        Arrays.fill(this.dataQueue, (byte)0);
        this.bitsInQueue = 0;
        this.squeezing = false;
        this.bitsAvailableForSqueezing = 0;
        this.fixedOutputLength = capacity / 2;
        this.chunk = new byte[rate / 8];
        this.oneByte = new byte[1];
    }

    private void absorbQueue()
    {
        KeccakAbsorb(state, dataQueue,rate / 8);

        bitsInQueue = 0;
    }

    protected void absorb(byte[] data, int off, long databitlen)
    {
        if ((bitsInQueue % 8) != 0)
        {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        }
        if (squeezing)
        {
            throw new IllegalStateException("attempt to absorb while squeezing");
        }

        long i = 0;
        while (i < databitlen)
        {
            if ((bitsInQueue == 0) && (databitlen >= rate) && (i <= (databitlen - rate)))
            {
                int wholeBlocks = (int)((databitlen - i) / rate);
                int offSet = off + (int)(i/8);
                for (int j = 0; j < wholeBlocks; j++)
                {
                    System.arraycopy(data, offSet, chunk, 0, chunk.length);

//                            displayIntermediateValues.displayBytes(1, "Block to be absorbed", curData, rate / 8);

                    KeccakAbsorb(state, chunk, chunk.length);
                    offSet += chunk.length;
                }

                i += wholeBlocks * rate;
            }
            else
            {
                int partialBlock = (int)(databitlen - i);
                if (partialBlock + bitsInQueue > rate)
                {
                    partialBlock = rate - bitsInQueue;
                }
                int partialByte = partialBlock % 8;
                partialBlock -= partialByte;

                System.arraycopy(data, off + (int)(i / 8), dataQueue, bitsInQueue / 8, partialBlock / 8);

                bitsInQueue += partialBlock;
                i += partialBlock;
                if (bitsInQueue == rate)
                {
                    absorbQueue();
                }
                if (partialByte > 0)
                {
                    int mask = (1 << partialByte) - 1;
                    dataQueue[bitsInQueue / 8] = (byte)(data[off + ((int)(i / 8))] & mask);
                    bitsInQueue += partialByte;
                    i += partialByte;
                }
            }
        }
    }

    private void padAndSwitchToSqueezingPhase()
    {
        if (bitsInQueue + 1 == rate)
        {
            dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
            absorbQueue();
            clearDataQueueSection(0, rate / 8);
        }
        else
        {
            clearDataQueueSection((bitsInQueue + 7) / 8, rate / 8 - (bitsInQueue + 7) / 8);
            dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
        }
        dataQueue[(rate - 1) / 8] |= 1 << ((rate - 1) % 8);
        absorbQueue();


//            displayIntermediateValues.displayText(1, "--- Switching to squeezing phase ---");


        if (rate == 1024)
        {
            KeccakExtract1024bits(state, dataQueue);
            bitsAvailableForSqueezing = 1024;
        }
        else

        {
            KeccakExtract(state, dataQueue, rate / 64);
            bitsAvailableForSqueezing = rate;
        }

//            displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);

        squeezing = true;
    }

    protected void squeeze(byte[] output, int offset, long outputLength)
    {
        long i;
        int partialBlock;

        if (!squeezing)
        {
            padAndSwitchToSqueezingPhase();
        }
        if ((outputLength % 8) != 0)
        {
            throw new IllegalStateException("outputLength not a multiple of 8");
        }

        i = 0;
        while (i < outputLength)
        {
            if (bitsAvailableForSqueezing == 0)
            {
                keccakPermutation(state);

                if (rate == 1024)
                {
                    KeccakExtract1024bits(state, dataQueue);
                    bitsAvailableForSqueezing = 1024;
                }
                else

                {
                    KeccakExtract(state, dataQueue, rate / 64);
                    bitsAvailableForSqueezing = rate;
                }

//                    displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);

            }
            partialBlock = bitsAvailableForSqueezing;
            if ((long)partialBlock > outputLength - i)
            {
                partialBlock = (int)(outputLength - i);
            }

            System.arraycopy(dataQueue, (rate - bitsAvailableForSqueezing) / 8, output, offset + (int)(i / 8), partialBlock / 8);
            bitsAvailableForSqueezing -= partialBlock;
            i += partialBlock;
        }
    }

    private void KeccakAbsorb(byte[] byteState, byte[] data, int dataInBytes)
    {
        keccakPermutationAfterXor(byteState, data, dataInBytes);
    }

    private static void fromBytesToWords(long[] stateAsWords, byte[] state)
    {
        for (int i = 0; i < (1600 / 64); i++)
        {
            stateAsWords[i] = bytesToWord(state, i * 8);
        }
    }

    private static long bytesToWord(byte[] state, int off)
    {
        return ((long)state[off + 0] & 0xff)
            | (((long)state[off + 1] & 0xff) << 8)
            | (((long)state[off + 2] & 0xff) << 16)
            | (((long)state[off + 3] & 0xff) << 24)
            | (((long)state[off + 4] & 0xff) << 32)
            | (((long)state[off + 5] & 0xff) << 40)
            | (((long)state[off + 6] & 0xff) << 48)
            | (((long)state[off + 7]) << 56);
    }

    private static void fromWordsToBytes(byte[] state, long[] stateAsWords)
    {
        for (int i = 0; i < (1600 / 64); i++)
        {
            wordToBytes(stateAsWords[i], state, i * 8);
        }
    }

    private static void wordToBytes(long word, byte[] state, int off)
    {
        state[off + 0] = (byte)(word);
        state[off + 1] = (byte)(word >>> (8 * 1));
        state[off + 2] = (byte)(word >>> (8 * 2));
        state[off + 3] = (byte)(word >>> (8 * 3));
        state[off + 4] = (byte)(word >>> (8 * 4));
        state[off + 5] = (byte)(word >>> (8 * 5));
        state[off + 6] = (byte)(word >>> (8 * 6));
        state[off + 7] = (byte)(word >>> (8 * 7));
    }

    private final long[] longState = new long[state.length / 8];
    private final long[] tempA = new long[state.length / 8];

    private void keccakPermutation(byte[] state)
    {

        fromBytesToWords(longState, state);

//        displayIntermediateValues.displayStateAsBytes(1, "Input of permutation", longState);

        keccakPermutationOnWords(longState);

//        displayIntermediateValues.displayStateAsBytes(1, "State after permutation", longState);

        fromWordsToBytes(state, longState);
    }

    private void keccakPermutationAfterXor(byte[] state, byte[] data, int dataLengthInBytes)
    {
        for (int i = 0; i < dataLengthInBytes; i++)
        {
            state[i] ^= data[i];
        }

        keccakPermutation(state);
    }

    private void keccakPermutationOnWords(long[] state)
    {
//        displayIntermediateValues.displayStateAs64bitWords(3, "Same, with lanes as 64-bit words", state);

        for (int i = 0; i < 24; i++)
        {
//            displayIntermediateValues.displayRoundNumber(3, i);

            theta(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After theta", state);

            rho(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After rho", state);

            pi(state, tempA);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After pi", state);

            chi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After chi", state);

            iota(state, i);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After iota", state);
        }
    }

    private static long leftRotate(long v, int r)
    {
        return (v << r) | (v >>> -r);
    }

    private static void theta(long[] A)
    {
        long C0 = A[0 + 0] ^ A[0 + 5] ^ A[0 + 10] ^ A[0 + 15] ^ A[0 + 20];
        long C1 = A[1 + 0] ^ A[1 + 5] ^ A[1 + 10] ^ A[1 + 15] ^ A[1 + 20];
        long C2 = A[2 + 0] ^ A[2 + 5] ^ A[2 + 10] ^ A[2 + 15] ^ A[2 + 20];
        long C3 = A[3 + 0] ^ A[3 + 5] ^ A[3 + 10] ^ A[3 + 15] ^ A[3 + 20];
        long C4 = A[4 + 0] ^ A[4 + 5] ^ A[4 + 10] ^ A[4 + 15] ^ A[4 + 20];

        long dX = leftRotate(C1, 1) ^ C4;
                       
        A[0] ^= dX;
        A[5] ^= dX;
        A[10] ^= dX;
        A[15] ^= dX;
        A[20] ^= dX;

        dX = leftRotate(C2, 1) ^ C0;

        A[1] ^= dX;
        A[6] ^= dX;
        A[11] ^= dX;
        A[16] ^= dX;
        A[21] ^= dX;

        dX = leftRotate(C3, 1) ^ C1;

        A[2] ^= dX;
        A[7] ^= dX;
        A[12] ^= dX;
        A[17] ^= dX;
        A[22] ^= dX;

        dX = leftRotate(C4, 1) ^ C2;

        A[3] ^= dX;
        A[8] ^= dX;
        A[13] ^= dX;
        A[18] ^= dX;
        A[23] ^= dX;

        dX = leftRotate(C0, 1) ^ C3;

        A[4] ^= dX;
        A[9] ^= dX;
        A[14] ^= dX;
        A[19] ^= dX;
        A[24] ^= dX;
    }

    private static void rho(long[] A)
    {
        // KeccakRhoOffsets[0] == 0
        for (int x = 1; x < 25; x++)
        {
            A[x] = leftRotate(A[x], KeccakRhoOffsets[x]);
        }
    }

    private static void pi(long[] A, long[] tempA)
    {
        System.arraycopy(A, 0, tempA, 0, tempA.length);

        A[0 + 5 * ((0 * 1 + 3 * 0) % 5)] = tempA[0 + 5 * 0];
        A[1 + 5 * ((0 * 1 + 3 * 1) % 5)] = tempA[0 + 5 * 1];
        A[2 + 5 * ((0 * 1 + 3 * 2) % 5)] = tempA[0 + 5 * 2];
        A[3 + 5 * ((0 * 1 + 3 * 3) % 5)] = tempA[0 + 5 * 3];
        A[4 + 5 * ((0 * 1 + 3 * 4) % 5)] = tempA[0 + 5 * 4];

        A[0 + 5 * ((2 * 1 + 3 * 0) % 5)] = tempA[1 + 5 * 0];
        A[1 + 5 * ((2 * 1 + 3 * 1) % 5)] = tempA[1 + 5 * 1];
        A[2 + 5 * ((2 * 1 + 3 * 2) % 5)] = tempA[1 + 5 * 2];
        A[3 + 5 * ((2 * 1 + 3 * 3) % 5)] = tempA[1 + 5 * 3];
        A[4 + 5 * ((2 * 1 + 3 * 4) % 5)] = tempA[1 + 5 * 4];

        A[0 + 5 * ((2 * 2 + 3 * 0) % 5)] = tempA[2 + 5 * 0];
        A[1 + 5 * ((2 * 2 + 3 * 1) % 5)] = tempA[2 + 5 * 1];
        A[2 + 5 * ((2 * 2 + 3 * 2) % 5)] = tempA[2 + 5 * 2];
        A[3 + 5 * ((2 * 2 + 3 * 3) % 5)] = tempA[2 + 5 * 3];
        A[4 + 5 * ((2 * 2 + 3 * 4) % 5)] = tempA[2 + 5 * 4];

        A[0 + 5 * ((2 * 3 + 3 * 0) % 5)] = tempA[3 + 5 * 0];
        A[1 + 5 * ((2 * 3 + 3 * 1) % 5)] = tempA[3 + 5 * 1];
        A[2 + 5 * ((2 * 3 + 3 * 2) % 5)] = tempA[3 + 5 * 2];
        A[3 + 5 * ((2 * 3 + 3 * 3) % 5)] = tempA[3 + 5 * 3];
        A[4 + 5 * ((2 * 3 + 3 * 4) % 5)] = tempA[3 + 5 * 4];

        A[0 + 5 * ((2 * 4 + 3 * 0) % 5)] = tempA[4 + 5 * 0];
        A[1 + 5 * ((2 * 4 + 3 * 1) % 5)] = tempA[4 + 5 * 1];
        A[2 + 5 * ((2 * 4 + 3 * 2) % 5)] = tempA[4 + 5 * 2];
        A[3 + 5 * ((2 * 4 + 3 * 3) % 5)] = tempA[4 + 5 * 3];
        A[4 + 5 * ((2 * 4 + 3 * 4) % 5)] = tempA[4 + 5 * 4];
    }

    private static void chi(long[] A)
    {
        long chiC0, chiC1, chiC2, chiC3, chiC4;

        for (int yBy5 = 0; yBy5 < 25; yBy5 += 5)
        {
            chiC0 = A[0 + yBy5] ^ ((~A[(((0 + 1) % 5) + yBy5)]) & A[(((0 + 2) % 5) + yBy5)]);
            chiC1 = A[1 + yBy5] ^ ((~A[(((1 + 1) % 5) + yBy5)]) & A[(((1 + 2) % 5) + yBy5)]);
            chiC2 = A[2 + yBy5] ^ ((~A[(((2 + 1) % 5) + yBy5)]) & A[(((2 + 2) % 5) + yBy5)]);
            chiC3 = A[3 + yBy5] ^ ((~A[(((3 + 1) % 5) + yBy5)]) & A[(((3 + 2) % 5) + yBy5)]);
            chiC4 = A[4 + yBy5] ^ ((~A[(((4 + 1) % 5) + yBy5)]) & A[(((4 + 2) % 5) + yBy5)]);

            A[0 + yBy5] = chiC0;
            A[1 + yBy5] = chiC1;
            A[2 + yBy5] = chiC2;
            A[3 + yBy5] = chiC3;
            A[4 + yBy5] = chiC4;
        }
    }

    private static void iota(long[] A, int indexRound)
    {
        A[(((0) % 5) + 5 * ((0) % 5))] ^= KeccakRoundConstants[indexRound];
    }

    private static void KeccakExtract1024bits(byte[] byteState, byte[] data)
    {
        System.arraycopy(byteState, 0, data, 0, 128);
    }


    private static void KeccakExtract(byte[] byteState, byte[] data, int laneCount)
    {
        System.arraycopy(byteState, 0, data, 0, laneCount * 8);
    }
}
